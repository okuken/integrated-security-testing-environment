package okuken.iste.logic;

import java.util.List;
import java.util.Map;

import static org.mybatis.dynamic.sql.SqlBuilder.*;

import com.google.common.collect.Maps;

import okuken.iste.dao.auto.PluginProjectOptionDynamicSqlSupport;
import okuken.iste.dao.auto.PluginProjectOptionMapper;
import okuken.iste.dto.PluginProjectOptionDto;
import okuken.iste.entity.auto.PluginProjectOption;
import okuken.iste.util.DbUtil;
import okuken.iste.util.SqlUtil;

public class ProjectOptionLogic {

	private static final ProjectOptionLogic instance = new ProjectOptionLogic();
	private ProjectOptionLogic() {}
	public static ProjectOptionLogic getInstance() {
		return instance;
	}

	public Map<String, Map<String, PluginProjectOptionDto>> loadPluginProjectOptions(Integer projectId) {
		var options =
			DbUtil.withSession(session -> {
				PluginProjectOptionMapper mapper = session.getMapper(PluginProjectOptionMapper.class);
				return mapper.select(c -> c
						.where(PluginProjectOptionDynamicSqlSupport.fkProjectId, isEqualTo(projectId))
						.orderBy(PluginProjectOptionDynamicSqlSupport.id));
			});

		return convertPluginProjectOptionEntitysToMap(options);
	}
	private Map<String, Map<String, PluginProjectOptionDto>> convertPluginProjectOptionEntitysToMap(List<PluginProjectOption> options) {
		Map<String, Map<String, PluginProjectOptionDto>> ret = Maps.newHashMap();
		options.forEach(option -> {
			var pluginName = option.getPluginName();
			if(!ret.containsKey(pluginName)) {
				ret.put(pluginName, Maps.newHashMap());
			}
			ret.get(pluginName).put(option.getKey(), convertPluginProjectOptionEntityToDto(option));
		});
		return ret;
	}
	private PluginProjectOptionDto convertPluginProjectOptionEntityToDto(PluginProjectOption entity) {
		var ret = new PluginProjectOptionDto();
		ret.setId(entity.getId());
		ret.setKey(entity.getKey());
		ret.setVal(entity.getVal());
		return ret;
	}

	public void savePluginProjectOption(Integer projectId, String pluginName, PluginProjectOptionDto dto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			var mapper = session.getMapper(PluginProjectOptionMapper.class);

			var entity = new PluginProjectOption();
			entity.setFkProjectId(projectId);
			entity.setPluginName(pluginName);
			entity.setKey(dto.getKey());
			entity.setVal(dto.getVal());
			entity.setPrcDate(now);

			mapper.insert(entity);
			dto.setId(entity.getId());
		});
	}

	public void updatePluginProjectOption(PluginProjectOptionDto dto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			var mapper = session.getMapper(PluginProjectOptionMapper.class);

			var entity = mapper.selectByPrimaryKey(dto.getId()).get();
			entity.setVal(dto.getVal());
			entity.setPrcDate(now);

			mapper.updateByPrimaryKey(entity);
		});
	}

}
