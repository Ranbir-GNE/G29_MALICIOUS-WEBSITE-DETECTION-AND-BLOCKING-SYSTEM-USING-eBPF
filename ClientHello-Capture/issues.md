
- a quote not ended in query issue sometimes (possible fix)

- This issue is possibly fixed after migrating to mysql
```
  ERROR:  invalid byte sequence for encoding "UTF8": 0xe4 0x12 0x31

  terminate called after throwing an instance of 'pqxx::data_exception'
    what():  ERROR:  invalid byte sequence for encoding "UTF8": 0xe4 0x12 0x31

  Aborted
```


- Need to handle the ACK's after TH_FIN in process_packet, since they clog up the memory (It now possibly clears after TH_FIN or TH_RST are finally executed. Havent tested yet)