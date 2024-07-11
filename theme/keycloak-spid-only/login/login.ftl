<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
    <div id="kc-form">
        <!-- SPID -->
        <#if social.providers??>
          <div class="spid-title">${msg("login.spid.access")}</div>
          <div class="spid-info">
              ${msg("login.spid.info")?no_esc}
          </div>
          <div class="spid-info-links">
              <span class="spid-info-link"><a href="https://www.spid.gov.it">${msg("login.spid.more-info")}</a></span>
              <span class="spid-info-link"><a href="https://www.spid.gov.it/richiedi-spid">${msg("login.spid.dont-have")}</a></span>
              <span class="spid-info-link"><a href="https://www.spid.gov.it/serve-aiuto">${msg("login.spid.need-help")}</a></span>
          </div>
          <div class="spid-idp-button-box">
              <a href="#" class="italia-it-button italia-it-button-size-m button-spid" spid-idp-button="#spid-idp-button-medium-get" aria-haspopup="true" aria-expanded="false">
                  <span class="italia-it-button-icon"><img src="${url.resourcesPath}/img/spid-ico-circle-bb.svg" onerror="this.src='img/spid-ico-circle-bb.png'; this.onerror=null;" alt="" /></span>
                  <span class="italia-it-button-text">${msg("login.spid.enter")}</span>
              </a>
              <div id="spid-idp-button-medium-get" class="spid-idp-button spid-idp-button-tip spid-idp-button-relative">
                  <ul id="spid-idp-list-medium-root-get" class="spid-idp-button-menu" aria-labelledby="spid-idp">
                      <li class="spid-idp-button-link" id="arubaid" data-idp="arubaid">
                          <a href="#"><span class="spid-sr-only">Aruba ID</span><img src="${url.resourcesPath}/img/spid-idp-arubaid.svg" onerror="this.src='img/spid-idp-arubaid.png'; this.onerror=null;" alt="Aruba ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="teamsystemid" data-idp="teamsystemid">
                          <a href="#"><span class="spid-sr-only">TeamSystem ID</span><img src="${url.resourcesPath}/img/spid-idp-teamsystemid.svg" onerror="this.src='img/spid-idp-teamsystemid.png'; this.onerror=null;" alt="TeamSystem ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="etnaid" data-idp="etnaid">
                           <a href="#"><span class="spid-sr-only">Etna ID</span><img src="${url.resourcesPath}/img/spid-idp-etnaid.svg" onerror="this.src='img/spid-idp-etnaid.png'; this.onerror=null;" alt="Etna ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="sielteid" data-idp="sielteid">
                           <a href="#"><span class="spid-sr-only">Sielte ID</span><img src="${url.resourcesPath}/img/spid-idp-sielteid.svg" onerror="this.src='img/spid-idp-sielteid.png'; this.onerror=null;" alt="Sielte ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="infocertid" data-idp="infocertid">
                          <a href="#"><span class="spid-sr-only">Infocert ID</span><img src="${url.resourcesPath}/img/spid-idp-infocertid.svg" onerror="this.src='img/spid-idp-infocertid.png'; this.onerror=null;" alt="Infocert ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="infocamereid" data-idp="infocamereid">
                          <a href="#"><span class="spid-sr-only">Infocamere ID</span><img src="${url.resourcesPath}/img/spid-idp-infocamereid.svg" onerror="this.src='img/spid-idp-infocamereid.png'; this.onerror=null;" alt="Infocamere ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="lepidaid" data-idp="lepidaid">
                          <a href="#"><span class="spid-sr-only">Lepida ID</span><img src="${url.resourcesPath}/img/spid-idp-lepidaid.svg" onerror="this.src='img/spid-idp-lepidaid.png'; this.onerror=null;" alt="Lepida ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="namirialid" data-idp="namirialid">
                          <a href="#"><span class="spid-sr-only">Namirial ID</span><img src="${url.resourcesPath}/img/spid-idp-namirialid.svg" onerror="this.src='img/spid-idp-namirialid.png'; this.onerror=null;" alt="Namirial ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="posteid" data-idp="posteid">
                          <a href="#"><span class="spid-sr-only">Poste ID</span><img src="${url.resourcesPath}/img/spid-idp-posteid.svg" onerror="this.src='img/spid-idp-posteid.png'; this.onerror=null;" alt="Poste ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="spiditaliaid" data-idp="spiditaliaid">
                          <a href="#"><span class="spid-sr-only">SPIDItalia Register.it</span><img src="${url.resourcesPath}/img/spid-idp-spiditalia.svg" onerror="this.src='img/spid-idp-spiditalia.png'; this.onerror=null;" alt="SpidItalia" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="timid" data-idp="timid">
                          <a href="#"><span class="spid-sr-only">Tim ID</span><img src="${url.resourcesPath}/img/spid-idp-timid.svg" onerror="this.src='img/spid-idp-timid.png'; this.onerror=null;" alt="Tim ID" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="intesigroupid" data-idp="intesigroupid">
                         <a href="#"><span class="spid-sr-only">Intesi Group</span><img src="${url.resourcesPath}/img/spid-idp-intesigroup.svg" onerror="this.src='img/spid-idp-intesigroup.png'; this.onerror=null;" alt="Intesi Group" /></a>
                      </li>
                      <li class="spid-idp-button-link" id="spidtestidp" data-idp="spidtestidp">
                          <a href="#"><span class="spid-sr-only">spidtestidp</span><img src="${url.resourcesPath}/img/spid-idp-test.svg" alt="spidtestidp" /> SPID SAML Check (Public)</a>
                      </li>
                      <li class="spid-idp-button-link" id="privatespid" data-idp="privatespid">
                          <a href="#"><span class="spid-sr-only">privatespid</span><img src="${url.resourcesPath}/img/spid-idp-test.svg" alt="privatespid" /> SPID SAML Check (Private)</a>
                      </li>
                      <li class="spid-idp-support-link">
                          <a href="https://www.spid.gov.it">${msg("login.spid.more-info")}</a>
                      </li>
                      <li class="spid-idp-support-link">
                          <a href="https://www.spid.gov.it/richiedi-spid">${msg("login.spid.dont-have")}</a>
                      </li>
                      <li class="spid-idp-support-link">
                          <a href="https://www.spid.gov.it/serve-aiuto">${msg("login.spid.need-help")}</a>
                      </li>
                  </ul>
              </div>
          </div>
        <div class="spid-logo"><img src="${url.resourcesPath}/img/spid-agid-logo-lb.png" alt="" /></div>

      <script src="${url.resourcesPath}/js/jquery.min.js"></script>
          <script src="${url.resourcesPath}/js/spid-sp-access-button.min.js"></script>
          <script>
            $(document).ready(function () {
                var rootList = $("#spid-idp-list-medium-root-get");
                var idpList = rootList.children(".spid-idp-button-link");
                var lnkList = rootList.children(".spid-idp-support-link");
                while (idpList.length) {
                    rootList.append(idpList.splice(Math.floor(Math.random() * idpList.length), 1)[0]);
                }
                rootList.append(lnkList);
            });

          </script>

          <script>
            window.spidproviders={
                <#list social.providers as p>
                "${p.alias}": "${p.loginUrl?no_esc}",
                </#list>
            }
            // social provider is the key, dom id is the value
            window.spidprovidermatch = {
                "spidtestidp": "spidtestidp",
                "privatespid": "privatespid",
                "arubaid": "arubaid",
                "etnaid": "etnaid",
                "infocertid": "infocertid",
                "infocamereid": "infocamereid",
                "lepidaid": "lepidaid",
                "namirialid": "namirialid",
                "posteid": "posteid",
                "sielteid": "sielteid",
                "spiditaliaid": "spiditaliaid",
                "teamsystemid": "teamsystemid",
                "intesigroupid": "intesigroupid",
                "timid": "timid"
            }
            $(document).ready(function(){
                for (const [key, value] of Object.entries(spidprovidermatch)) {
                    const url = spidproviders[key]
                    let currElem = $("#"+value+" a")[0]
                    console.log("url:"+url+" id:"+value);
                    if(url !==undefined && currElem!==undefined){
                        currElem.href = url
                    }
                }
            });

          </script>
        </#if>
        <!-- END OF SPID -->

    </div>
    </#if>

</@layout.registrationLayout>

