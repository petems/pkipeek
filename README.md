# pkipeek

A golang project to replicate the output from `openssl x509 -in testdata/example.pem -text`

Current WIP: 

```
./main testdata/rsa-certificate.pem
Certificate:
    Data:
        Version: 3
        Serial Number: 4 (0x0004)
    Signature Algorithm: SHA256-RSA
    Issuer: CN=Puppet CA: puppet.vm
        Validity:
            Not Before: 2020-10-22 13:03:36 +0000 UTC
            Not After: 2025-10-22 13:03:36 +0000 UTC
        Subject: CN=node1.vm
        Subject Public Key Info:
            Public Key Algorithm: RSA
                Public-Key: (4096 bit):
                Modulus:
                    c2:e9:2e:de:95:d7:b7:d4:8f:c8:44:98:d1:e3:0e:4a:ab:be:4d:26:9d:ae:51:
                    d2:ab:26:74:72:5a:9f:f3:90:74:ea:85:e3:12:73:07:5a:c3:6a:eb:b3:9d:1c:
                    0d:6b:73:65:07:75:2c:5a:7e:a2:9d:7c:99:47:0f:85:7f:87:0c:81:1b:a1:6a:
                    b4:5e:96:b0:c7:75:79:db:31:23:ad:da:dc:f5:c2:87:6d:52:af:12:af:07:35:
                    eb:9e:d9:96:85:db:49:cf:98:af:ab:74:f2:ac:46:04:67:05:56:09:4d:86:8a:
                    7c:06:6a:09:2f:40:47:54:76:a7:c0:94:07:99:c7:e3:f2:0e:ad:21:cf:ea:71:
                    4b:bd:3d:71:73:48:42:97:2c:b4:e1:76:d7:ba:04:9a:fb:11:39:07:14:ba:ba:
                    82:c0:e1:d7:4c:c5:da:e7:02:ca:0c:dc:58:f5:37:46:e9:ba:c3:17:ee:3a:82:
                    26:a9:6b:5b:7e:12:1b:78:08:1d:7c:da:ff:a4:34:18:43:c7:e5:ca:2f:e0:95:
                    4a:c2:33:b2:f9:23:5a:9a:3d:f4:a0:12:8a:2c:f8:b4:74:7d:f5:5d:8a:3f:33:
                    e8:08:df:cc:84:c4:0a:b2:57:a1:bb:91:67:6b:02:8d:b5:d1:d7:3c:4c:ba:08:
                    e0:e2:90:0c:47:2a:8f:c5:9b:98:ee:bc:0a:73:88:1a:d3:31:44:58:79:8d:db:
                    fb:ed:1f:26:1b:21:37:25:73:99:ce:53:95:10:dc:ea:5d:d3:91:58:e4:2d:a1:
                    18:40:70:0a:30:cc:05:5b:ee:16:4e:67:52:62:89:97:52:8a:38:00:5b:56:78:
                    bc:7f:b9:a5:ce:63:43:4b:60:9f:e7:94:96:53:68:cc:51:6f:3e:c8:03:d9:e1:
                    d2:33:80:a2:aa:31:be:75:da:52:3f:d9:b2:5f:3e:6e:12:a5:95:13:42:fc:fb:
                    30:80:0e:30:3d:2e:2a:17:55:8b:45:d1:ee:a3:cc:d4:b3:c8:1e:17:a9:00:3e:
                    97:9a:43:68:b2:e6:b9:d4:c7:93:bb:29:c5:f3:47:76:4d:a3:6e:c9:69:3d:ed:
                    dc:4e:7f:f4:b4:4e:a3:45:c2:47:60:a7:97:1c:db:cc:ca:26:28:27:52:a9:72:
                    85:03:34:94:14:5d:b2:2d:b3:db:5c:f8:e5:46:c6:0f:e2:67:1c:4b:cf:30:c4:
                    6e:6f:51:8f:e3:a7:73:d8:8c:1a:a7:2d:b0:4f:85:d5:8d:b6:be:39:ae:3a:96:
                    9c:6a:15:72:b3:2c:a7:c5:62:55:e4:bd:02:21:c8:c5:43:3b:de:6b:04:d6:8c:
                    f3:73:d5:58:7d:1f
                Exponent: 65537 (0x10001)
            X509v3 extensions:
                Netscape certificate comment:
                  Puppet Server Internal Certificate
                X509v3 Authority key identifier:
                  keyid:֬d6:ac:e3:76:1d:72:cd:84:85:ce:3b:0f:ef:8a:25:39:90:a2:18:e0
                Subject key identifier:
                  c3:ef:56:14:48:4f:f0:38:68:0b:8a:1a:c4:9a:de:6a:89:80:15:10
                Unknown (1.3.6.1.4.1.34380.1.1.22)
                  0x0000 0c 07 76 61 75 6c 74 6f |..vaulto|
                  0x0008 6b                      |k       |
                X509v3 Basic Constraints: critical
                  CA:֬FALSE
                Extended key usage: critical
                  server authentication (1.3.6.1.5.5.7.3.1)
                  client authentication (1.3.6.1.5.5.7.3.2)
                Key usage: critical
                  digital signature (0)
                  key encipherment (2)
        Signature Algorithm: SHA256-RSA
            3e:43:e6:7e:14:2a:2f:24:d2:b1:58:21:34:20:71:fb:ff:ee:ec:8f:73:43:d6:4f:
            e3:7d:c6:3b:3a:41:6f:22:32:21:01:52:8b:af:f1:da:2a:3a:69:af:00:45:c5:6a:
            e7:0f:5e:e9:14:24:19:a7:32:cc:df:a0:dd:62:b7:cc:5d:28:04:8d:35:b9:fa:3b:
            32:aa:e9:8c:3f:1b:a3:80:27:d2:bc:28:9c:cd:da:8e:e0:1a:ff:33:13:23:0f:7a:
            1d:12:b6:19:77:42:38:1e:0a:a9:73:72:9e:d7:0d:f5:a3:8b:7b:e1:9f:52:8f:68:
            61:3d:68:4f:c7:6f:7e:41:32:8e:2d:b4:10:c8:10:d9:97:6f:b0:07:74:17:c3:92:
            60:1c:5f:a9:8c:fa:51:8a:65:3a:45:21:cf:74:0d:bd:0b:ec:87:65:5e:54:7b:4b:
            c6:3b:cf:d6:94:23:6d:15:b2:ff:76:67:ee:aa:5a:b7:df:d6:b8:e6:88:73:75:85:
            1b:c3:d4:2b:e2:d3:14:48:1f:70:fa:e0:24:3e:3b:2e:96:50:3f:30:93:ae:74:08:
            e0:7c:f7:5f:cb:5a:fd:95:52:a8:90:de:0a:63:39:0a:2f:d8:19:55:f2:1b:4e:f5:
            b3:b3:4a:cd:9a:34:ca:b4:97:41:55:93:8f:d3:66:9b:26:a5:29:a4:8b:4e:dd:88:
            dd:5c:e8:08:29:74:bc:4a:2f:cc:88:7e:01:9b:51:57:9f:15:98:e7:a2:9e:e0:65:
            8e:91:53:f3:bb:9b:f1:01:ff:92:9e:2c:0c:58:a5:38:43:e9:26:da:ae:86:90:da:
            79:b1:b1:29:1b:9b:7a:85:0b:c8:55:23:66:fc:4c:2f:3e:a3:e3:ff:fa:21:e7:c7:
            26:97:b0:b9:4e:4d:fd:48:25:0a:ef:59:de:a6:d0:87:b0:39:c8:e7:b1:25:69:79:
            96:9d:12:51:53:24:ca:38:ef:9d:cf:09:12:51:c0:86:de:ed:78:b2:0c:3e:9a:88:
            62:9a:b8:73:1b:f7:9b:39:8b:e2:2c:f5:01:9e:75:6d:40:61:38:5e:ad:46:ce:ad:
            84:36:16:95:a7:d5:f7:0c:f1:0a:57:4b:ed:a4:f6:93:0b:62:e7:bf:99:50:1c:6c:
            93:4c:d0:3c:70:8c:eb:86:f6:e2:45:3a:ac:c1:ad:5f:b2:f6:d9:0d:6d:33:ec:8a:
            fd:e1:32:19:1a:28:ea:0c:b3:6a:96:f1:fd:c4:ec:12:35:52:24:5b:37:1b:2e:39:
            55:7b:5b:27:05:04:f5:bc:4c:ac:01:99:c4:63:18:71:ba:6f:f4:a7:98:e6:d3:de:
            54:3b:56:71:ad:55:cd:5f
-----BEGIN CERTIFICATE-----
MIIFfjCCA2agAwIBAgIBBDANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRQdXBw
ZXQgQ0E6IHB1cHBldC52bTAeFw0yMDEwMjIxMzAzMzZaFw0yNTEwMjIxMzAzMzZa
MBMxETAPBgNVBAMMCG5vZGUxLnZtMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAwuku3pXXt9SPyESY0eMOSqu+TSadrlHSqyZ0clqf85B06oXjEnMHWsNq
67OdHA1rc2UHdSxafqKdfJlHD4V/hwyBG6FqtF6WsMd1edsxI63a3PXCh21SrxKv
BzXrntmWhdtJz5ivq3TyrEYEZwVWCU2GinwGagkvQEdUdqfAlAeZx+PyDq0hz+px
S709cXNIQpcstOF217oEmvsROQcUurqCwOHXTMXa5wLKDNxY9TdG6brDF+46giap
a1t+Eht4CB182v+kNBhDx+XKL+CVSsIzsvkjWpo99KASiiz4tHR99V2KPzPoCN/M
hMQKslehu5FnawKNtdHXPEy6CODikAxHKo/Fm5juvApziBrTMURYeY3b++0fJhsh
NyVzmc5TlRDc6l3TkVjkLaEYQHAKMMwFW+4WTmdSYomXUoo4AFtWeLx/uaXOY0NL
YJ/nlJZTaMxRbz7IA9nh0jOAoqoxvnXaUj/Zsl8+bhKllRNC/PswgA4wPS4qF1WL
RdHuo8zUs8geF6kAPpeaQ2iy5rnUx5O7KcXzR3ZNo27JaT3t3E5/9LROo0XCR2Cn
lxzbzMomKCdSqXKFAzSUFF2yLbPbXPjlRsYP4mccS88wxG5vUY/jp3PYjBqnLbBP
hdWNtr45rjqWnGoVcrMsp8ViVeS9AiHIxUM73msE1ozzc9VYfR8CAwEAAaOB0DCB
zTAxBglghkgBhvhCAQ0EJBYiUHVwcGV0IFNlcnZlciBJbnRlcm5hbCBDZXJ0aWZp
Y2F0ZTAfBgNVHSMEGDAWgBTWrON2HXLNhIXOOw/viiU5kKIY4DAdBgNVHQ4EFgQU
w+9WFEhP8DhoC4oaxJreaomAFRAwGAYLKwYBBAGCjEwBARYECQwHdmF1bHRvazAM
BgNVHRMBAf8EAjAAMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAO
BgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQADggIBAD5D5n4UKi8k0rFYITQg
cfv/7uyPc0PWT+N9xjs6QW8iMiEBUouv8doqOmmvAEXFaucPXukUJBmnMszfoN1i
t8xdKASNNbn6OzKq6Yw/G6OAJ9K8KJzN2o7gGv8zEyMPeh0Sthl3QjgeCqlzcp7X
DfWji3vhn1KPaGE9aE/Hb35BMo4ttBDIENmXb7AHdBfDkmAcX6mM+lGKZTpFIc90
Db0L7IdlXlR7S8Y7z9aUI20Vsv92Z+6qWrff1rjmiHN1hRvD1Cvi0xRIH3D64CQ+
Oy6WUD8wk650COB891/LWv2VUqiQ3gpjOQov2BlV8htO9bOzSs2aNMq0l0FVk4/T
ZpsmpSmki07diN1c6AgpdLxKL8yIfgGbUVefFZjnop7gZY6RU/O7m/EB/5KeLAxY
pThD6SbaroaQ2nmxsSkbm3qFC8hVI2b8TC8+o+P/+iHnxyaXsLlOTf1IJQrvWd6m
0IewOcjnsSVpeZadElFTJMo4753PCRJRwIbe7XiyDD6aiGKauHMb95s5i+Is9QGe
dW1AYTherUbOrYQ2FpWn1fcM8QpXS+2k9pMLYue/mVAcbJNM0DxwjOuG9uJFOqzB
rV+y9tkNbTPsiv3hMhkaKOoMs2qW8f3E7BI1UiRbNxsuOVV7WycFBPW8TKwBmcRj
GHG6b/SnmObT3lQ7VnGtVc1f
-----END CERTIFICATE-----
```