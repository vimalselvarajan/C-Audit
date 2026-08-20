#ifndef CAUDIT_FIXTURE_KEYS_H
#define CAUDIT_FIXTURE_KEYS_H

/* This header is excluded by configuration in the tests that use it. Nothing
   in it may reach an assembled prompt, including the marker below. */
#define DEPLOY_TOKEN "ZZTOP-THIS-STRING-MUST-NEVER-BE-TRANSMITTED"

static const char kFixturePrivateKey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAxNotARealKeyJustFixtureBytesForTheRedactionTest\n"
    "-----END RSA PRIVATE KEY-----\n";

#endif
