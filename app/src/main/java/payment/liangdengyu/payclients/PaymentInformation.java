package payment.liangdengyu.payclients;

import com.google.gson.annotations.SerializedName;

public class PaymentInformation {

    @SerializedName("disbursementAccount")
    private String disbursementAccount;  // E.g., Bank account number or similar ID
    @SerializedName("alternatePassword")
    private String alternatePassword;   // Can be hashed for security
    @SerializedName("paymentAmount")
    private String paymentAmount;       // Can be changed to BigDecimal for better precision if required
    @SerializedName("merchantAccount")
    private String merchantAccount;     // E.g., Merchant's account number or ID


    public String toJsonString() {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"disbursementAccount\":\"").append(this.disbursementAccount).append("\",");
        json.append("\"alternatePassword\":\"").append(alternatePassword).append("\",");
        json.append("\"paymentAmount\":\"").append(paymentAmount).append("\",");
        json.append("\"merchantAccount\":\"").append(merchantAccount).append("\"");
        json.append("}");
        return json.toString();
    }
    public PaymentInformation(String disbursementAccount, String alternatePassword, String paymentAmount, String merchantAccount) {
        this.disbursementAccount = disbursementAccount;
        this.alternatePassword = alternatePassword;
        this.paymentAmount = paymentAmount;
        this.merchantAccount = merchantAccount;
    }

    // Getters and Setters
    public String getDisbursementAccount() {
        return disbursementAccount;
    }

    public void setDisbursementAccount(String disbursementAccount) {
        this.disbursementAccount = disbursementAccount;
    }

    public String getAlternatePassword() {
        return alternatePassword;
    }

    public void setAlternatePassword(String alternatePassword) {
        this.alternatePassword = alternatePassword;
    }

    public String getPaymentAmount() {
        return paymentAmount;
    }

    public void setPaymentAmount(String paymentAmount) {
        this.paymentAmount = paymentAmount;
    }

    public String getMerchantAccount() {
        return merchantAccount;
    }

    public void setMerchantAccount(String merchantAccount) {
        this.merchantAccount = merchantAccount;
    }

    // Other methods and business logic can be added if necessary
}
