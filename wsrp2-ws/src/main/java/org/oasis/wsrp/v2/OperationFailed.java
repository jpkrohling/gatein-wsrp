
package org.oasis.wsrp.v2;

import javax.xml.ws.WebFault;


/**
 * This class was generated by the JAX-WS RI.
 * JAX-WS RI 2.1.3-b02-
 * Generated source version: 2.0
 * 
 */
@WebFault(name = "OperationFailed", targetNamespace = "urn:oasis:names:tc:wsrp:v2:types")
public class OperationFailed
    extends Exception
{

    /**
     * Java type that goes as soapenv:Fault detail element.
     * 
     */
    private OperationFailedFault faultInfo;

    /**
     * 
     * @param message
     * @param faultInfo
     */
    public OperationFailed(String message, OperationFailedFault faultInfo) {
        super(message);
        this.faultInfo = faultInfo;
    }

    /**
     * 
     * @param message
     * @param faultInfo
     * @param cause
     */
    public OperationFailed(String message, OperationFailedFault faultInfo, Throwable cause) {
        super(message, cause);
        this.faultInfo = faultInfo;
    }

    /**
     * 
     * @return
     *     returns fault bean: org.oasis.wsrp.v2.OperationFailedFault
     */
    public OperationFailedFault getFaultInfo() {
        return faultInfo;
    }

}