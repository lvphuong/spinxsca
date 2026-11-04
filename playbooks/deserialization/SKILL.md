---
name: deserialization
description: "Insecure deserialization of attacker-controlled data."
allowed_tools: [read_file, search_code]
categories: [INSECURE_DESERIALIZATION, CODE_INJECTION, PROTOTYPE_POLLUTION]
---
# Insecure deserialization of attacker-controlled data.

1. Sinks: `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal`, Java `ObjectInputStream.readObject`, Jackson default typing, `node-serialize`, `unserialize` in PHP, `BinaryFormatter`.
2. Trace the bytes to request bodies, cookies, message queues or files users can upload.
3. Prototype pollution: deep merge or path setters (`_.merge`, `_.set`, `defaultsDeep`) with user-controlled keys like `__proto__` or `constructor.prototype`.
4. Controls that count: safe loaders, type allow-lists, signed payloads verified before parsing, JSON with schema validation.
5. Code execution from deserialization is CRITICAL when reachable without authentication.
