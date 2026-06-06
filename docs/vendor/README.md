# Vendored third-party assets

These files are committed copies of upstream packages, pinned to
specific versions, distributed alongside hypershunt's documentation so
the docs site renders identically on GitHub Pages and inside any
fresh hypershunt install (no internet egress required).

Every file in this directory is **MIT licensed**.  Hypershunt itself
is BSD-2-Clause; MIT is permissive and compatible.  The
copyright notices below are reproduced as MIT requires.

## Manifest

| File                          | Upstream                                                   | Version  | License |
|-------------------------------|------------------------------------------------------------|----------|---------|
| `docsify.min.js`              | [docsify](https://github.com/docsifyjs/docsify)            | 4.13.1   | MIT     |
| `vue.css`                     | [docsify](https://github.com/docsifyjs/docsify)            | 4.13.1   | MIT     |
| `search.min.js`               | [docsify](https://github.com/docsifyjs/docsify) (plugin)   | 4.13.1   | MIT     |
| `docsify-copy-code.min.js`    | [docsify-copy-code](https://github.com/jperasmus/docsify-copy-code) | 3.0.0    | MIT     |
| `prism.min.js`                | [PrismJS](https://github.com/PrismJS/prism)                | 1.29.0   | MIT     |
| `prism-bash.min.js`           | [PrismJS](https://github.com/PrismJS/prism) (component)    | 1.29.0   | MIT     |
| `prism-json.min.js`           | [PrismJS](https://github.com/PrismJS/prism) (component)    | 1.29.0   | MIT     |
| `prism-yaml.min.js`           | [PrismJS](https://github.com/PrismJS/prism) (component)    | 1.29.0   | MIT     |

Files were fetched from jsdelivr's npm mirror; the minified
copies preserve their upstream attribution headers where the
original projects emit them (Prism, docsify-copy-code).

## Copyright notices

### docsify (incl. `vue.css` and `search.min.js`)

```
The MIT License (MIT)

Copyright (c) 2017-present QingWei Li

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### docsify-copy-code

```
MIT License

Copyright (c) 2017-2023 JP Erasmus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### PrismJS (incl. `prism-bash.min.js`, `prism-json.min.js`, `prism-yaml.min.js`)

```
MIT LICENSE

Copyright (c) 2012 Lea Verou

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## Refreshing

To upgrade any of these files, re-fetch from jsdelivr at a
pinned version, e.g.

```sh
curl -sSfLo docs/vendor/docsify.min.js \
    https://cdn.jsdelivr.net/npm/docsify@<version>/lib/docsify.min.js
```

and update the **Version** column above.  Keep the version pinned
(don't fetch `@latest`) so the docs site is reproducible.
