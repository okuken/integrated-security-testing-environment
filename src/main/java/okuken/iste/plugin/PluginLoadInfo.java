package okuken.iste.plugin;

/**
 * [CAUTION] saved as JSON
 */
public class PluginLoadInfo {

	private String jarFilePath;
	private boolean loaded;

	public PluginLoadInfo(String jarFilePath, boolean loaded) {
		this.jarFilePath = jarFilePath;
		this.loaded = loaded;
	}

	public String getJarFilePath() {
		return jarFilePath;
	}
	public void setJarFilePath(String jarFilePath) {
		this.jarFilePath = jarFilePath;
	}
	public boolean isLoaded() {
		return loaded;
	}
	public void setLoaded(boolean loaded) {
		this.loaded = loaded;
	}

}
