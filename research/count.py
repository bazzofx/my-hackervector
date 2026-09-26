import re
f = r"C:\_DeepSeekApps\my-hackvertor\research\unbescape-src\org\unbescape\html\Html5EscapeSymbolsInitializer.java"
t = open(f, encoding="latin-1").read()
rows = re.findall(r'addReference\(\s*[^,]+,\s*"([^"]*)"\)', t)
print("HTML5 single-codepoint rows:", len(rows))
print("  ending with ';':", sum(1 for r in rows if r.endswith(";")))
print("  legacy no-semicolon:", sum(1 for r in rows if not r.endswith(";")))
f4 = r"C:\_DeepSeekApps\my-hackvertor\research\unbescape-src\org\unbescape\html\Html4EscapeSymbolsInitializer.java"
t4 = open(f4, encoding="latin-1").read()
rows4 = re.findall(r'addReference\(\s*[^,]+,\s*"([^"]*)"\)', t4)
print("HTML4 rows:", len(rows4), " all end with ';':", all(r.endswith(";") for r in rows4))
