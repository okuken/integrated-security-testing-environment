package okuken.iste.util;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.google.gson.Gson;

public class IsteUtil {

	private static final String ISTE_URL = "https://github.com/okuken/integrated-security-testing-environment";

	private static final String ISTE_RELEASES_URL = "https://github.com/okuken/integrated-security-testing-environment/releases";

	private static final String ISTE_REFS_URL = "https://github.com/okuken/integrated-security-testing-environment/refs?type=tag";
	private static final String ISTE_REFS_JSON_KEY = "refs";

	private static final String INFO_PROPERTIES_PATH = "/iste.properties";
	private static Properties info;

	public static String getUrl() {
		return ISTE_URL;
	}

	public static String getReleasesUrl() {
		return ISTE_RELEASES_URL;
	}

	public static String getVersion() {
		return getInfo("version");
	}

	private static String getInfo(String key) {
		if(info == null) {
			loadInfo();
		}
		return info.getProperty(key);
	}
	private static void loadInfo() {
		try {
			info = new Properties();
			info.load(IsteUtil.class.getResourceAsStream(INFO_PROPERTIES_PATH));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static String fetchIsteLatestVersion() throws IOException, InterruptedException {
		return fetchAllIsteVersions().get(0);
	}
	@SuppressWarnings("unchecked")
	private static List<String> fetchAllIsteVersions() throws IOException, InterruptedException {

		var request = HttpRequest.newBuilder()
						.uri(URI.create(ISTE_REFS_URL))
						.header("Accept", "application/json")
						.build();

		var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		if(response.statusCode() != 200) {
			throw new RuntimeException("fetch versions failed. status:" + response.statusCode());
		}

		var responseJson = new Gson().fromJson(response.body(), Map.class);
		return (List<String>)responseJson.get(ISTE_REFS_JSON_KEY);
	}

}
