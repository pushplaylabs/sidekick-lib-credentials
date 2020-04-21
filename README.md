# Library Credentials

## Quickstart

```sh
npm i -S git+ssh://git@github.com/pushplaylabs/sidekick-lib-credentials#master
```

And start use in your code:

```js
import { init } from 'sidekick-lib-credentials'

const {
  prepareUserCredentials,
  initRecoveryKey,
  createKeySet,
  createEncryptedKeySet,
  createEncryptedCredential,
  createCredential,
} = init()
```
