const ts = require('typescript');
const express = require('express');
const app = express();
app.use(express.json());

app.post('/extract-types', (req, res) => {
    const { filePath, functionText } = req.body;
    let finalSignature = "";

    if (!filePath) {
        return res.status(400).json({ error: 'filePath is required' });
    }

    const program = ts.createProgram([filePath], { 
        target: ts.ScriptTarget.ESNext,
        moduleResolution: ts.ModuleResolutionKind.NodeJs,
        allowJs: true, 
        resolveJsonModule: true 
    });
    
    const checker = program.getTypeChecker();
    const sourceFile = program.getSourceFile(filePath);

    if (!sourceFile) {
        return res.status(404).json({ error: 'File not found in TS Program' });
    }

    let extractedSignatures = new Set();

    function extractSymbolInfo(symbol, name, isNamespace = false) {
        if (!symbol) return;

        if (functionText && typeof functionText === 'string') {
            const nameRegex = new RegExp(`\\b${name}\\b`);
            if (!nameRegex.test(functionText)) {
                return;
            }
        }

        if (symbol.flags & ts.SymbolFlags.Alias) {
            symbol = checker.getAliasedSymbol(symbol);
        }

        if (isNamespace) {
            const exports = checker.getExportsOfModule(symbol);
            let namespaceContent = `declare namespace ${name} {\n`;
            let addedAnyMethod = false; 
            
            exports.forEach(exp => {
                if (functionText && typeof functionText === 'string') {
                    const expRegex = new RegExp(`\\b${exp.name}\\b`);
                    if (!expRegex.test(functionText)) {
                        return; 
                    }
                }

                const expType = checker.getTypeOfSymbolAtLocation(exp, exp.valueDeclaration || sourceFile);
                const expTypeStr = checker.typeToString(expType, undefined, ts.TypeFormatFlags.NoTruncation);
                namespaceContent += `  export const ${exp.name}: ${expTypeStr};\n`;
                addedAnyMethod = true;
            });
            
            namespaceContent += `}`;
            
            if (addedAnyMethod) {
                extractedSignatures.add(namespaceContent);
            }

        } else {
            const type = checker.getTypeOfSymbolAtLocation(symbol, symbol.valueDeclaration || sourceFile);
            const typeString = checker.typeToString(type, undefined, ts.TypeFormatFlags.NoTruncation);
            extractedSignatures.add(`// Origin of Import: ${name}\ndeclare const ${name}: ${typeString};`);
        }
    }

    function visit(node) {
        if (ts.isImportDeclaration(node)) {
            const modulePath = node.moduleSpecifier.text.toLowerCase();
            
            if (modulePath.includes('challenge')) {
                return;
            }

            const importClause = node.importClause;
            if (!importClause) return;

            if (importClause.name) {
                const symbol = checker.getSymbolAtLocation(importClause.name);
                extractSymbolInfo(symbol, importClause.name.text, false);
            }

            if (importClause.namedBindings) {
                if (ts.isNamespaceImport(importClause.namedBindings)) {
                    const symbol = checker.getSymbolAtLocation(importClause.namedBindings.name);
                    extractSymbolInfo(symbol, importClause.namedBindings.name.text, true);
                }
                else if (ts.isNamedImports(importClause.namedBindings)) {
                    importClause.namedBindings.elements.forEach(element => {
                        const symbol = checker.getSymbolAtLocation(element.name);
                        extractSymbolInfo(symbol, element.name.text, false);
                    });
                }
            }
        }

        if (ts.isVariableDeclaration(node) && node.initializer && ts.isCallExpression(node.initializer)) {
            const callExpr = node.initializer;
            
            if (callExpr.expression.getText() === 'require' && callExpr.arguments.length > 0) {
                const arg = callExpr.arguments[0];
                
                if (ts.isStringLiteral(arg)) {
                    const modulePath = arg.text.toLowerCase();
                    
                    if (modulePath.includes('challenge')) return;

                    if (node.name && ts.isIdentifier(node.name)) {
                        const symbolName = node.name.text;
                        const symbol = checker.getSymbolAtLocation(node.name);
                        
                        extractSymbolInfo(symbol, symbolName, true); 
                    }
                }
            }
        }
        
        ts.forEachChild(node, visit);
    }

    visit(sourceFile);
    
   res.json({ type_context: Array.from(extractedSignatures).join('\n\n') });
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`🛡️ Type-Extractor running on port ${PORT}`);
});