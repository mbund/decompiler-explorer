# Decompiler Explorer

Watch for changes in a binary and output a C-like decompilation.

## Usage

Use something like [entr](https://github.com/eradman/entr) to watch for changes in a file and recompile.

```bash
examples$ find . -name '*.c' | entr make
```

Then also watch with the decompiler explorer.

```bash
examples$ decompiler-explorer -o output.gc ./program
```

`output.gc` is the default output file, where `.gc` is short for "ghidra-like C"

## VSCode tips

Set the language mode of the outputted C like code to `C#` or some other language where you don't have a language server set up that will just give errors, but still has good syntax highlighting.

Run `File: Toggle Active Editor Read-only in Session` to set the outputted C like code to read only, since it will always be overwritten by Decompiler Explorer if your source binary changes.
