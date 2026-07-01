# Development

Use JDK21, as the ASM Stuff does not exist anymore in JDK25:

```bash
nix shell n#jdk21
```

To compile the sourcecode:

```bash
javac -d out \
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
  src/com/loader/*.java
```

Then create out jar:

```bash
jar cfm loader.jar MANIFEST.MF -C out .
```

Then start Burpsuite with it:

```bash
steam-run /nix/store/v3n6jl0sxn64g97c5kxzriwj4fv6qnjh-openjdk-21.0.12+2/bin/java --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED -javaagent:loader.jar -jar /nix/store/5ylfm58cxa0qffss0plmzbll27jw9rnw-burpsuite.jar --suppress-jre-check --i-accept-the-license-agreement --disable-auto-update --disable-check-for-updates-dialog --temporary-project --unpause-spider-and-scanner
```

And to test the activation by changing the preferences path:

```bash
steam-run /nix/store/v3n6jl0sxn64g97c5kxzriwj4fv6qnjh-openjdk-21.0.12+2/bin/java -Duser.home=/tmp --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED -javaagent:loader.jar -jar /nix/store/5ylfm58cxa0qffss0plmzbll27jw9rnw-burpsuite.jar --suppress-jre-check --i-accept-the-license-agreement --disable-auto-update --disable-check-for-updates-dialog --temporary-project --unpause-spider-and-scanner
```

The community edition can still be used via this cli flag:

```bash
--product-mode=community
```
