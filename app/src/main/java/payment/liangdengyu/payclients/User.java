package payment.liangdengyu.payclients;

import java.math.BigDecimal;

public class User {
    private Long id;

    private String username;
    private String password;
    private BigDecimal amount;
    private boolean enabled;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
        this.amount = BigDecimal.ZERO;
        this.enabled = true;
    }
    public User(Long id, String username, String password, String amount, boolean enabled) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.amount = new BigDecimal(amount);
        this.enabled = enabled;
    }

    public User() {
        this.username = "";
        this.password = "";
        this.amount = BigDecimal.ZERO;
    }

    public Long getId() {
        return id;
    }

    public BigDecimal saveAmount(BigDecimal num) {
        amount = amount.add(num);
        return amount;
    }

    public BigDecimal withdrawAmount(BigDecimal num) {
        amount = amount.subtract(num);
        return amount;
    }


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public BigDecimal getAmount() {
        return amount;
    }
    public void setAmount(BigDecimal num) {
        this.amount = num;
    }
}
