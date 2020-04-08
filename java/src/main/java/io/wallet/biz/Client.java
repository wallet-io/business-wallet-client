package io.wallet.biz;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;

import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.ParseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bitcoinj.core.SignatureDecodeException;

public class Client {

    private static final String PRV_KEY = "a937fc6a79e0ad67a259bb74a1fb89289d30aafe39395a45959f51e463af18ef";
    private static final String PUB_KEY = "036afd5d8ddbb3434ebd14a91d0a1e71b4a5d35dc526ac488732e306ad4cf28a59";
    private static final String SERVER_KEY = "0201f423cd5bb21aafede6841e105bfa078f372a6c11840960f3c5152714f6754b";
    private static final String HOST = "https://business.wallet.io";

    private String privateKey = PRV_KEY;
    private String publicKey = PUB_KEY;
    private String serverKey = SERVER_KEY;
    private String host = HOST;

    public static Map<String, String> generateKey() {
        return Utils.generateKey();
    }

    public Client(String privateKey, String publicKey, String serverKey, String host) {
        if (privateKey != null) {
            this.privateKey = privateKey;
        }
        if (publicKey != null) {
            this.publicKey = publicKey;
        }
        if (serverKey != null) {
            this.serverKey = serverKey;
        }
        if (host != null) {
            this.host = host;
        }
    }

    public String call(String path, Map<String, Object> params)
            throws HttpException, IOException, ApiException, ParseException, ResponseVerificationException {
        Map<String, String> headers = this.getHeader("post", path, params);
        String result = this.post(path, params, headers, 80000);
        // return (Map<String, Object>) JSON.parse(result);
        return result;
    }

    private Map<String, String> getHeader(String method, String path, Map<String, Object> params) {
        String timestamp = String.valueOf(new Date().getTime());
        if (params == null) {
            params = new HashMap<String, Object>();
        }
        String data = JSON.toJSONString(params, SerializerFeature.SortField.MapSortField);

        String signatureSubject = method.toUpperCase() + "|" + path + "|" + data + "|" + timestamp;
        String sign = Utils.ecKeySign(signatureSubject, privateKey);

        Map<String, String> header = new HashMap<String, String>();
        header.put("content-type", "application/json;charset=utf-8");
        header.put("api-auth-key", publicKey);
        header.put("api-auth-timestamp", timestamp);
        header.put("api-auth-sign", sign);

        return header;
    }

    private String post(String path, Object bodyObj, Map<String, String> header, int timeout)
            throws HttpException, IOException, ApiException, ParseException, ResponseVerificationException {

        HttpPost httpPost = new HttpPost(this.host + path);
        if (header != null && !header.isEmpty()) {
            for (String key : header.keySet()) {
                httpPost.addHeader(key, header.get(key));
            }
        }

        StringEntity entity = new StringEntity(JSON.toJSONString(bodyObj), "utf-8");
        httpPost.setEntity(entity);
        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpResponse response = httpClient.execute(httpPost);
        String result = EntityUtils.toString(response.getEntity(), "utf-8");

        if (response.getStatusLine().getStatusCode() != 200) {
            throw new ApiException(response, result);
        }
        this.verifyResponse("post", path, response, result);
        return result;
    }

    private void verifyResponse(String method, String path, CloseableHttpResponse response, String result)
            throws ParseException, IOException, ResponseVerificationException {
        Header authSignHeader = response.getFirstHeader("api-resp-sign");
        if (authSignHeader == null) {
            throw new ResponseVerificationException("no server api-resp-sign header");
        }

        String authSign = authSignHeader.getValue();
        Header authTimestampHeader = response.getFirstHeader("api-resp-timestamp");
        String authTimestamp = authTimestampHeader.getValue();

        String signatureSubject = method.toUpperCase() + "|" + path + "|" + response.getStatusLine().getStatusCode()
                + "|" + JSONObject.toJSONString(JSON.parse(result), SerializerFeature.SortField.MapSortField) + "|"
                + authTimestamp;

        Boolean verifyResult;
        try {
            verifyResult = Utils.ecPubKeyVerify(signatureSubject, authSign, this.serverKey);
        } catch (SignatureDecodeException e) {
            throw new ResponseVerificationException("server sign SignatureDecodeException");
        }

        if (!verifyResult) {
            throw new ResponseVerificationException("server response verification error");
        }

    }

}
