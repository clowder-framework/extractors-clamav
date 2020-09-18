# Virus Checker for Clowder

If enabled, this will run a virus check on any file and add to metadata any results. For example:

```
database:
  bytecode:
    version: 331
    sigs: 94
    built: 2019-09-19T16:12:33
  daily:
    version: 25931
    sigs: 4319278
    built: 2020-09-17T13:53:56
  main:
    version: 59
    sigs: 4564902
    built: 2019-11-25T13:56:15
  signatures: 8884274
scan:
  infected: false
  virus: null
```

In case of an infection it will list the actual virus detected:

```
scan:
  infected: true
  virus: Win.Test.EICAR_HDB-1 FOUND
```
