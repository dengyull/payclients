package payment.liangdengyu.payclients;


import static payment.liangdengyu.payclients.PreferenceUtil.globaluser;

import java.io.Serializable;
import java.math.BigDecimal;

public class ProductInformation implements Serializable {
    private Long id;
    private String productMode;
    private String manufacturer;
    private BigDecimal unitCost;
    public ProductInformation() {}

    public ProductInformation(String productMode, String manufacturer, BigDecimal unitCost) {
        this.id = globaluser.getId();
        this.productMode = productMode;
        this.manufacturer = manufacturer;
        this.unitCost = unitCost;
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getProductMode() {
        return productMode;
    }

    public void setProductMode(String productMode) {
        this.productMode = productMode;
    }

    public String getManufacturer() {
        return manufacturer;
    }

    public void setManufacturer(String manufacturer) {
        this.manufacturer = manufacturer;
    }

    public BigDecimal getUnitCost() {
        return unitCost;
    }

    public void setUnitCost(BigDecimal unitCost) {
        this.unitCost = unitCost;
    }

    public String toString(){
        String str = "productMode: "+productMode;
        str += "\nmanufacturer: " + manufacturer;
        str += "\nunitCost: "+unitCost;
        //str += "\nid: "+globaluser.getId();
        return str;
    }
    public String sentString(){
        String str = "productMode: "+productMode;
        str += "\nmanufacturer: " + manufacturer;
        str += "\nunitCost: "+unitCost;
        str += "\nid: "+globaluser.getId();
        return str;
    }
}
