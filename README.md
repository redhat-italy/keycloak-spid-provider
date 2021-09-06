# keycloak-spid-provider

Italian SPID authentication provider for Keycloak v.9.0.3+ (https://www.keycloak.org/)

This guide describe the steps required to successfully integrate a Keycloak environment with the SPID federation.

## Prerequisites

- Keycloak full-working installation (version *9.0.3+*): the following instructions expect an environment variable named **$KC_HOME** to be set to the base directory of the Keycloak instance
- Docker installed
- JDK 8+
- git
- Maven

## Install keycloak-spid-provider

### Build jar file

Clone this git repository and build it using Maven:

```shell
$ git clone https://github.com/redhat-italy/keycloak-spid-provider.git
$ cd keycloak-spid-provider
$ mvn clean package
```

After a successful build you will find the `spid-provider.jar` jar file in the `target` directory.

### Deploy into Keycloak

The instructions consider a *standalone* installation but are applicable to *managed domain* installations as well (changing the target directory names where it is required).

Shutdown the Keycloak server.

Copy the jar file into Keycloack `deployments` directory.

```shell
$ cp target/spid-provider.jar $KC_HOME/standalone/deployments/
```

> **Note**
> 
> Each time you copy the jar file in the `deployments` directory, Keycloak automatically deploys it at the bootstrap. Nevertheless it may happen that the previous version of the same deployment doesn't get overridden.
> 
> It is recommended to cleanup any existing installed deployment in $KC_HOME/standalone/data/content/ related to the same jar module, before restarting Keycloak.

Also copy the file `realm.js` located in `src/main/resources/theme-resources/resources/js/controllers` into the Keycloak base theme directory
`$KC_HOME/themes/base/admin/resources/js/controllers`

```shell
$ cp src/main/resources/theme-resources/resources/js/controllers/realm.js $KC_HOME/themes/base/admin/resources/js/controllers
```

> **Note**
>
> The `realm.js` file doesn't get automatically deployed with jar file at this moment: for this reason it must be manually copied.
> 
> For convenience, a future version will deploy both the jar and js files inside a Docker container running the Keycloak instance.

Start Keycloak server:

```shell
$ $KC_HOME/bin/standalone.sh -b 0.0.0.0
```

The bind address is set to *0.0.0.0* to listen on any interface, in order to relax any network configuration issue.

During Keycloak bootstrap you should see log entries like the following:

```
10:13:25,178 INFO  [org.jboss.as.server.deployment] (MSC service thread 1-4) WFLYSRV0027: Starting deployment of "spid-provider.jar" (runtime-name: "spid-provider.jar")

...
10:13:32,178 INFO  [org.keycloak.subsystem.server.extension.KeycloakProviderDeploymentProcessor] (MSC service thread 1-4) Deploying Keycloak provider: spid-provider.jar
...

10:13:34,044 INFO  [org.jboss.as.server] (ServerService Thread Pool -- 33) WFLYSRV0010: Deployed "spid-provider.jar" (runtime-name : "spid-provider.jar")
```

The SPID custom provider has been correctly deployed and to verify that the module is correctly available and active, you can open the Keycloak admin console and access the **Identity Providers** section, choose the **Add provider** dropdown and you should find the **SPID** entry.

## Repeated deployments and cache

In order to deploy a modified version of the jar file, you can just repeat the deployment commands described above. However sometimes Keycloak caches don't get flushed when a new deployment occurs: in that case a quick workaround is to edit `$KC_HOME/standalone/configuration/standalone.xml` file and temporary disable the theme/templates caching replacing this xml block:

```xml
<theme>
  <staticMaxAge>2592000</staticMaxAge>
  <cacheThemes>true</cacheThemes>
  <cacheTemplates>true</cacheTemplates>
  <dir>${jboss.home.dir}/themes</dir>
</theme>
```

with the following:

```xml
<theme>
  <staticMaxAge>-1</staticMaxAge>
  <cacheThemes>false</cacheThemes>
  <cacheTemplates>false</cacheTemplates>
  <dir>${jboss.home.dir}/themes</dir>
</theme>
```

Then restart Keycloak and it will reload the new resources from the jar package. Make sure you also clear your browser caches (or use *incognito mode*) when verifying the correct deployment. After the first reload you can turn back on the caches and restart Keycloak again (if required).

## Install and configure the local SPID TestEnv docker environment

The *SPID TestEnv docker environment* ([https://github.com/italia/spid-testenv2/](https://github.com/italia/spid-testenv2/)) is a Docker environment that "emulates" the online SPID Test IdP ([https://idptest.spid.gov.it/](https://idptest.spid.gov.it/)).

Although these testing solutions are very similar some performed checks are different, so it is recommended to test your service provider configuration with both them.

Clone the SPID TestEnv project repository:

```shell
$ git clone https://github.com/italia/spid-testenv2.git
$ cd spid-testenv2 
```

Since the current version does not include a mandatory patch described at this [link](https://github.com/italia/spid-testenv2/pull/327), we apply the patch manually.

Edit the file `testenv/crypto.py`.

Locate the following line (at the beginning):

```python
from signxml.exceptions import InvalidDigest, InvalidSignature as InvalidSignature_
```

and replace it with the following line:

```python
from signxml.exceptions import InvalidDigest, InvalidInput, InvalidSignature as InvalidSignature_
```

Then, inside the class `HTTPPostSignatureVerifier` definition, find the `def _verify_signature(self):` and replace:

```python
            self._verifier.verify(
                self._request.saml_request, x509_cert=self._cert)
```

with:

```python
            try:
                self._verifier.verify(
                    self._request.saml_request, x509_cert=self._cert)
            except InvalidInput as e:
                # Work around issue https://github.com/XML-Security/signxml/issues/143
                if "Use verify(ignore_ambiguous_key_info=True)" in str(e):
                    logger.info("Found both X509Data and KeyValue in XML signature, validating signature using X509Data only")
                    self._verifier.verify(
                        self._request.saml_request, x509_cert=self._cert,
                        ignore_ambiguous_key_info=True
                    )
                else:
                    raise e
```

Pay attention to indentation.

Now you can build the Docker image:

```shell
$ docker build -t italia/spid-testenv2:custom-fix .
```

> **Note**
> 
> The built image is tagged with *custom-fix* tag to distinguish it from the official one.

Create a configuration file:

```shell
$ cp conf/config.yaml.example conf/config.yaml
```

Run the container:

```shell
$ docker run --name spid-idp-demo -p 8088:8088 -v $(pwd)/conf:/app/conf --rm italia/spid-testenv2:custom-fix
```

The web server of the SPID TestEnv docker environment is now available at [http://localhost:8088](http://localhost:8088).

This test identity provider expose its metadata descriptor at [http://localhost:8088/metadata](http://localhost:8088/metadata). You will need this endpoint later to setup the Keycloak Identity Provider configuration.

To stop SPID TestEnv just kill the `docker run...` command with *CTRL+C*.

## Setup Identity Provider(s)

Come back to Keycloak admin console.

Select the target realm (or create one if required).

The following instructions can be reused to define all of the Identity Providers supported by SPID.

### Setup a custom "First Broker Login" Authentication Flow

This step is required because we want that if a user logs in with different identity providers (even different SPID authorized IDP), they are all linked to the same keycloak account (if already existent, otherwise it gets created).

However, even if the username is the same, Keycloak will trigger by default an "Existing Account Verification" step with link confirmation: since this is not desirable because we trust the information from SPID IdPs, we define a new *First Broker Login* Authentication Flow to automatically set the existing user.

1. In the Keycloak admin console, select the *Authentication* item from the left menu;
2. In the *Flows* tab, select *First Broker Login* and then click *Copy*;
3. Set the name of the new flow to *First Broker Login SPID*;
4. In the newly created *First Broker Login SPID* search for the *First Broker Login SPID Handle Existing Account* hierarchy entry and click on the *Actions* command on the right, then select *Add Execution*;
5. Choose the provider *Automatically Set Existing User* and click *Save*;
6. With the up/down arrows, move the new execution above the *Confirm Link Existing Account* entry;
7. Set the *Requirement* column radio button of the *Automatically Set Existing User* execution to *Required*
8. Set both the *Confirm Link Existing Account* and the *First Broker Login SPID Account Verification Options* radio buttons to *Disabled*.

### Identity Provider configuration

1. Select the *Identity Providers* item from the left menu, click on *Add provider*, then select *SPID*;
2. In the *Add Identity Provider* page, scroll to the bottom and set the *Import from URL* field to the provider metadata url endpoint [http://localhost:8088/metadata](http://localhost:8088/metadata) (SPID TestEnv must be running at this point);
3. Click on the Import button.

Most of the fields will be filled in automatically.

Fill in the other fields as follows (leave the other fields as set by default).

#### Main section
- **Alias**: enter a name for the provider (it will be used as an URL component, so DO NOT enter space characters)
- **Display Name**: the name of the IDP (it will be the name of the login button on the Keycloak login page)
- **Trust Email**: set to `ON`
- **First Login Flow**: select `First Broker Login SPID` (defined in the previous section)

#### SAML Config section
- **NameID Policy Format**: set to `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
- **Principal Type**: set to `Attribute [Name]`
- **Principal Attribute**: appears when *Principal Type* is set. Set it to `fiscalNumber`
- **Want AuthnRequests Signed**: set to `ON`
- **Want Assertions Signed**: set to `ON`
- **SAML Signature Key Name**: set to `NONE`
- **Validate Signature**: set to `ON`
- **Sign Service Provider Metadata**: set to `ON`
- **Attribute Consuming Service Index**: set to `1`. This corresponds to the index of the Attribute Consuming Service defined in your SP metadata - if you have more than one, you can change it to the value you need.
The following attributes are used to automatically generate a SPID compliant SAML SP metadata document.  
As the SPID SP metadata is actually the "union" of all of the metadata for the different IdPs, you will only need to set those in the first SPID IdP in alphabetical order. The values for all the other providers will be ignored, so just leave them blank.

- **Attribute Consuming Service Names**: comma separated list of localized service names. Each string should be entered in the format `<locale>|<text>` (e.g. `en|Online services,it|Servizi online`)
- **Organization Names, Organization Display Names, Organization URLs**: Localized data for the organization, same format as above (e.g. `en|Online services,it|Servizi online` for both *Names* and *Display Names*, for `en|http://localhost:8080` *URLs*)
- **Private SP**: set to `ON` if your organization is a private entity, `OFF` if it is a Public Administration
- **IPA Code** (Public SP only): Enter the IPA Code of the Public Administration
- **VAT Number**, **Fiscal Code** (Private SP only): Enter the VAT Number and the Fiscal Code of the private entity
- **Company Name (Other), Phone (Other), Email (Other)**: Technical contact info for the organization (any value is ok for testing purposes)
- **Company Name (Billing), Phone (Billing), Email (Billing)** (Private SP only): Billing contact info for the organization (any value is ok for testing purposes)

#### Requested AuthnContext Constraints section

Here you can specify which SPID Level you want to request to the IdP:

- **Comparison**: set to `Minimum` or `Exact` depending on your needs
- **AuthnContext ClassRefs**: enter - in order from the most preferred to the least preferred - one or more of the SPID Authentication Level classes. Valid values are:
  - `https://www.spid.gov.it/SpidL3`
  - `https://www.spid.gov.it/SpidL2`
  - `https://www.spid.gov.it/SpidL1`

Save the configuration.

### Configure Identity Provider Mappers

Click on the *Mappers* tab in the newly created *Identity Provider* configuration

Set the *User Name attribute*, the *Basic attributes* and, if required, one or more attribute mappers among *Other attributes*.

#### User Name attribute
Click on the *Create* button and set the following attributes:

| Name | Mapper Type	| Template |
| ---- | ---- | ---- |
| User Name	| SPID Username Template Importer | ${ATTRIBUTE.fiscalNumber} |

All SPID users will have their username set to their fiscalNumber (lowercased according to the Keycloak convention).

#### Basic attributes
First Name and Last Name are required to identify the user and should be always mapped to special Keycloak attributes. Define the following two required mappers:

| Name | Mapper Type | Attribute Name | User Attribute Name |
| ---- | ---- | ---- | ---- |
| First Name | SPID Attribute Importer | name | firstName |
| Last Name | SPID Attribute Importer | familyName | lastName |

> *NOTE**
> 
> Avoid mapping the email assertion to the basic email Keycloak attribute, in order to avoid dangerous security issue: users could trigger the *Forgot Password* flow, and set a local password for the SPID account. If this happens, you can't trust the user to have a valid SPID session.
> 
> It is much safer to map the email attribute to a SPID-specific attribute as described in the next paragraph.

#### Other attributes

All of the other SPID attributes are optional and follow the same convention. Refer to the following table as a guide:

| Name | Mapper Type | Attribute Name | User Attribute Name |
| ---- | ---- | ---- | ---- |
| SPID Code | SPID Attribute Importer | spidCode | spid-spidCode | 
| Email | SPID Attribute Importer | email | spid-email |
| Tax Id | SPID Attribute Importer | fiscalNumber | spid-fiscalNumber |
| Gender | SPID Attribute Importer | gender | spid-gender |
| Date of Birth | SPID Attribute Importer | dateOfBirth | spid-dateOfBirth |
| Place of Birth | SPID Attribute Importer | placeOfBirth | spid-placeOfBirth |
| County of Birth | SPID Attribute Importer | countyOfBirth | spid-countyOfBirth |
| Mobile Phone | SPID Attribute Importer | mobilePhone | spid-mobilePhone |
| Address | SPID Attribute Importer | address | spid-address |
| Digital Address | SPID Attribute Importer | digitalAddress | spid-digitalAddress |
| Company Name | SPID Attribute Importer | companyName | spid-companyName |
| Company Address | SPID Attribute Importer | registeredOffice | spid-registeredOffice |
| VAT Number | SPID Attribute Importer | ivaCode | spid-ivaCode |

## Generating and configuring Service Provider metadata

The SPID Service Provider metadata (xml) document can be automatically generated clicking on the *SPID Service Provider Metadata* link available in the *Identity Provider* configuration page (the same filled in the previous section) at the label *Endpoints*.

The link has the following standard format:

 `http(s)://<host>:<port>/auth/realms/<your_realm_name>/spid-sp-metadata`

> **NOTE**
> 
> All of the "shared" data (*Organization* fields, *Company* fields, etc.) in the metadata is actually set by the first SPID IdP in alphabetical order only. Thus, there is no need to copy the same data in all of the IdPs.
> 
> The attribute mappings in the AttributeConsumingService section are automatically populated from the configured Mappers for the first SPID IdPs in alphabetical order.

Configure the Service Provider Metadata in the *SPID TestEnv* server executing the following steps:

1. Click the *SPID Service Provider Metadata* link;
2. Save the generated xml file;
3. Stop the running *SPID TestEnv docker environment*;
4. Put the xml file in the `conf` directory under the *SPID TestEnv docker environment*, renaming it to `sp_metadata.xml` (to make the configuration easier).
5. Restart *SPID TestEnv docker environment* (use the same same `docker run ...` command);

Connecting to the *SPID TestEnv* at [http://localhost:8088](http://localhost:8088), you should see you Service Provider listed in the home page.

In the tab *Utenti* are listed some test user for login/logout tests.

## Testing login - logout

Now you can try to login using a configured client. For example you could use the built-in *Account* client application.

1. Browse to: `http://<host>:<port>:8080/auth/realms/<your_realm_name>/account/`;
2. The login page will appear, showing the IDP login button (and the usual local login form with username/password fields);
3. Click that button;
4. You should be redirected to the *SPID TestEnv* IDP login page;
5. Enter test/test as username/password values;
6. You will be asked to confirm the user information that are going to be shared with the Service Provider;
7. Approve the request;
8. You will be redirected to Keycloak, showing a form to complete user data (add the email with any string) and confirm;
9. You should be redirected to the *Account* application page showing user data acquired from the IDP;
10. Try to click the logout button to test also this flow.

## Acknowledgements
Some java code and html snippets are taken from or inspired by the same custom provider, developed by *Luca Leonardo Scorcia* for a newer version of Keycloack (v.12.0.0), available at [https://github.com/lscorcia/keycloak-spid-provider](https://github.com/lscorcia/keycloak-spid-provider).

This project is released under the Apache License 2.0, same as the main Keycloak package.
