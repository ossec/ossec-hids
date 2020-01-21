# 3.6.0

## Breaking changes

### empty pcre2 options raise an error

Previously empty `pcre2` options could be used:
`<program_name_pcre2></program_name_pcre2>`

This has been changed to raise an error.
Now there must be a value for these options:
`<program_name_pcre2>.*</program_name_pcre2>`

### maxminddb

geoip support has been replaced with [libmaxminddb](https://github.com/maxmind/libmaxminddb)
The maxminddb development package should be installed to enable geoip support.
The `geoipdb` configuration option has been re-used for the new database.
Testing has only been done with the `GeoLite2-Country.mmdb` database, and currently the country
`iso_code` is the only output.


