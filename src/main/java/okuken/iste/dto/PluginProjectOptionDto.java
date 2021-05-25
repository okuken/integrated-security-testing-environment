package okuken.iste.dto;

public class PluginProjectOptionDto {

	private Integer id;
	private String key;
	private String val;

	public PluginProjectOptionDto() {}
	public PluginProjectOptionDto(String key, String val) {
		this.key = key;
		this.val = val;
	}

	public Integer getId() {
		return id;
	}
	public String getKey() {
		return key;
	}
	public String getVal() {
		return val;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public void setVal(String val) {
		this.val = val;
	}

}
