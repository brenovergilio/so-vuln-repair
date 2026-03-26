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

    // Create the TS program allowing the resolution of local repository files
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

    // Use a Set to avoid duplicate declarations
    let extractedSignatures = new Set();

    // Core function that asks the compiler for the symbol SIGNATURE only, ignoring the body
    function extractSymbolInfo(symbol, name, isNamespace = false) {
        if (!symbol) return;

        // 🪓 A GUILHOTINA NÍVEL 1: O Import Principal
        // Verifica se o nome do import existe no texto da função como uma palavra isolada
        if (functionText && typeof functionText === 'string') {
            const nameRegex = new RegExp(`\\b${name}\\b`);
            if (!nameRegex.test(functionText)) {
                return; // O símbolo não é usado na função, aborta a extração instantaneamente!
            }
        }

        // If it's an alias (like an import), resolve it to the actual origin symbol
        if (symbol.flags & ts.SymbolFlags.Alias) {
            symbol = checker.getAliasedSymbol(symbol);
        }

        if (isNamespace) {
            // For 'import * as security', scan everything the file exports
            const exports = checker.getExportsOfModule(symbol);
            let namespaceContent = `declare namespace ${name} {\n`;
            let addedAnyMethod = false; // Flag para saber se sobrou algo após a poda
            
            exports.forEach(exp => {
                // 🪓 A GUILHOTINA NÍVEL 2: Poda Interna de Namespaces
                // Verifica se o método específico exportado foi usado na função
                if (functionText && typeof functionText === 'string') {
                    const expRegex = new RegExp(`\\b${exp.name}\\b`);
                    if (!expRegex.test(functionText)) {
                        return; // O método não é usado, pula para o próximo!
                    }
                }

                const expType = checker.getTypeOfSymbolAtLocation(exp, exp.valueDeclaration || sourceFile);
                // typeToString generates the clean signature (e.g., (user: User) => string)
                const expTypeStr = checker.typeToString(expType, undefined, ts.TypeFormatFlags.NoTruncation);
                namespaceContent += `  export const ${exp.name}: ${expTypeStr};\n`;
                addedAnyMethod = true;
            });
            
            namespaceContent += `}`;
            
            // Só adiciona o namespace ao prompt se pelo menos um método dele for usado
            if (addedAnyMethod) {
                extractedSignatures.add(namespaceContent);
            }

        } else {
            // For normal imports (default or named)
            const type = checker.getTypeOfSymbolAtLocation(symbol, symbol.valueDeclaration || sourceFile);
            const typeString = checker.typeToString(type, undefined, ts.TypeFormatFlags.NoTruncation);
            extractedSignatures.add(`// Origin of Import: ${name}\ndeclare const ${name}: ${typeString};`);
        }
    }

    // Navigate the Abstract Syntax Tree (AST) looking for the 3 forms of imports
    function visit(node) {
        if (ts.isImportDeclaration(node)) {
            // Extrai o caminho do arquivo que está sendo importado (ex: '../lib/insecurity')
            const modulePath = node.moduleSpecifier.text.toLowerCase();
            
            // REGRA 1: Exclusão total de artefatos de CTF (Data Leakage Prevention)
            if (modulePath.includes('challenge')) {
                return; // Ignora e pula para o próximo nó
            }

            const importClause = node.importClause;
            if (!importClause) return;

            // 1. Default Imports
            if (importClause.name) {
                const symbol = checker.getSymbolAtLocation(importClause.name);
                extractSymbolInfo(symbol, importClause.name.text, false);
            }

            if (importClause.namedBindings) {
                // 2. Namespace Imports 
                if (ts.isNamespaceImport(importClause.namedBindings)) {
                    const symbol = checker.getSymbolAtLocation(importClause.namedBindings.name);
                    extractSymbolInfo(symbol, importClause.namedBindings.name.text, true);
                }
                // 3. Named Imports 
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
            
            // Verifica se a função chamada é o "require"
            if (callExpr.expression.getText() === 'require' && callExpr.arguments.length > 0) {
                const arg = callExpr.arguments[0];
                
                if (ts.isStringLiteral(arg)) {
                    const modulePath = arg.text.toLowerCase();
                    
                    // Prevenção de Data Leakage (CTF)
                    if (modulePath.includes('challenge')) return;

                    if (node.name && ts.isIdentifier(node.name)) {
                        const symbolName = node.name.text; // Ex: 'path', 'fs', 'security'
                        const symbol = checker.getSymbolAtLocation(node.name);
                        
                        // Tratamos o require como um namespace (true) para extrair os seus métodos internos
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