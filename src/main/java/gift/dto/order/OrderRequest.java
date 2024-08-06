package gift.dto.order;

import java.time.LocalDateTime;

public class OrderRequest {
    private Long productId;
    private Long optionId;
    private int quantity;
    private String message;
    private LocalDateTime orderTime;
    private String email;
    private int point;

    public OrderRequest() {}

    public OrderRequest(Long productId, Long optionId, int quantity, int point, String message, LocalDateTime orderTime, String email) {
        this.productId = productId;
        this.optionId = optionId;
        this.quantity = quantity;
        this.message = message;
        this.orderTime = orderTime;
        this.email = email;
        this.point = point;
    }

    public Long getProductId() {
        return productId;
    }

    public Long getOptionId() {
        return optionId;
    }

    public int getQuantity() {
        return quantity;
    }

    public String getMessage() {
        return message;
    }

    public LocalDateTime getOrderTime() {
        return orderTime;
    }

    public String getEmail() {
        return email;
    }

    public int getPoint() {
        return point;
    }
}
