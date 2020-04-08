package io.wallet.biz;

import java.util.Map;

import com.alibaba.fastjson.JSON;

import org.apache.http.client.methods.CloseableHttpResponse;

public class ApiException extends Exception {

    private static final long serialVersionUID = 1L;
    private int httpCode;
    private String errorKey = null;
    private String errorMsg = null;
    private String responseTxt = null;

    public ApiException(int httpCode) {
        this.httpCode = httpCode;
    }

    public ApiException(int httpCode, String errorKey, String errorMsg) {
        this.httpCode = httpCode;
        this.errorKey = errorKey;
        this.errorMsg = errorMsg;
    }

    ApiException(CloseableHttpResponse response, String text) {
        this.httpCode = response.getStatusLine().getStatusCode();
        try {
            this.responseTxt = text;
            Map<String, Object> resultMap = (Map<String, Object>) JSON.parse(text);
            this.errorKey = (String) resultMap.get("error");
            this.errorMsg = (String) resultMap.get("msg");
        } catch (Exception e) {
        }
    }

    public int getHttpCode() {
        return httpCode;
    }

    public String getErrorKey() {
        return errorKey;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public String getResponseTxt() {
        return responseTxt;
    }

}