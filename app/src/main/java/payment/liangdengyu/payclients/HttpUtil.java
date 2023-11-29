package payment.liangdengyu.payclients;

import com.google.gson.JsonObject;

import java.io.IOException;
import java.time.Instant;

import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class HttpUtil {
    private static final OkHttpClient client = new OkHttpClient();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");


    public String getResponseAsString(String url) throws Exception {
        Request request = new Request.Builder()
                .url(url)
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) throw new Exception("Unexpected code " + response);

            // Return the response as a string
            return response.body().string();
        }
    }

    public static String post(String url, JsonObject json) throws IOException {
        OkHttpClient client = new OkHttpClient();

        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        RequestBody requestBody = RequestBody.create(JSON, json.toString());
        Request request = new Request.Builder()
                .url(url)
                .post(requestBody)
                .build();

        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        }
    }
    public static void sendStringToWebsite(String url, String jsonString, Callback callback) {
        RequestBody body = RequestBody.create(jsonString, JSON);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .build();
        client.newCall(request).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(okhttp3.Call call, IOException e) {
                // Handle failure
                callback.onFailure(e);
            }

            @Override
            public void onResponse(okhttp3.Call call, Response response) throws IOException {
                // Handle response
                if (!response.isSuccessful()) {
                    callback.onFailure(new IOException("Unexpected code " + response));
                } else {
                    callback.onSuccess(response.body().string());
                }
            }
        });
    }


    public interface Callback {
        void onSuccess(String response);
        void onFailure(Exception e);
    }

}
