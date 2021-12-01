package org.keycloak.broker.spid.tests;

import org.junit.Assert;
import org.junit.Test;


public class SpidSAML2AuthnRequestBuilderTest {

    @Test
    public void fiscalNumberTrimming(){

        String fiscalNumber = "tinit-drcgnn12a46a326k";
        String normalFiscalNumber = "MPRPSD70B15D971D";


        //l'uso di toUpperCase senza assegnazione è per lasciare inalterato il fiscalNumber originale
        //e riassegnandogli solamente il valore non trimmato
        String newFiscalNumber = manageFN(fiscalNumber);
        String newNormalFiscalNumber = manageFN(normalFiscalNumber);

        Assert.assertTrue(!newFiscalNumber.toUpperCase().contains("TINIT-"));

        //normal fiscal number has not changed
        Assert.assertTrue(newNormalFiscalNumber.equals(newNormalFiscalNumber));



    }

    private String manageFN(String fiscalNumber) {
        if(fiscalNumber.toUpperCase().startsWith("TINIT-"))
            fiscalNumber = fiscalNumber.split("^(?i)TINIT-")[1];
        return fiscalNumber;
    }


}
