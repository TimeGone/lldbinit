# lldb script from https://github.com/ryaoi/lldb-peda
#### with slight modify now

#### I like to add these code in .lldbinit:
```
command script import ~/Playground/Tools/lldbinit/lldbpeda.py
settings set stop-line-count-after 10
settings set stop-line-count-before 10
settings set stop-disassembly-count 10
settings set stop-disassembly-display always
```
