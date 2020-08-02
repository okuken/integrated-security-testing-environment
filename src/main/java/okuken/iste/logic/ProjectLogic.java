package okuken.iste.logic;

import java.awt.Frame;
import java.util.List;
import java.util.stream.Collectors;

import org.mybatis.dynamic.sql.select.SelectDSLCompleter;

import okuken.iste.dao.auto.ProjectDynamicSqlSupport;
import okuken.iste.dao.auto.ProjectMapper;
import okuken.iste.dto.ProjectDto;
import okuken.iste.entity.auto.Project;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.DbUtil;
import okuken.iste.util.SqlUtil;
import okuken.iste.view.option.ProjectSelectorDialog;

public class ProjectLogic {

	private static final ProjectLogic instance = new ProjectLogic();
	private ProjectLogic() {}
	public static ProjectLogic getInstance() {
		return instance;
	}

	public void selectProject() {
		Frame burpFrame = BurpUtil.getBurpSuiteJFrame();
		ProjectSelectorDialog projectSelectorDialog = new ProjectSelectorDialog(burpFrame);
		BurpUtil.getCallbacks().customizeUiComponent(projectSelectorDialog);
		projectSelectorDialog.setLocationRelativeTo(burpFrame);
		projectSelectorDialog.setVisible(true);
		ProjectDto projectDto = projectSelectorDialog.getSelectedProject();

		if(projectDto.getId() == null) {
			saveProject(projectDto);
		}
		ConfigLogic.getInstance().setProject(projectDto);
		ConfigLogic.getInstance().saveLastSelectedProjectName(projectDto.getName());
	}

	public List<ProjectDto> loadProjects() {
		List<Project> projects =
			DbUtil.withSession(session -> {
				ProjectMapper projectMapper = session.getMapper(ProjectMapper.class);
				return projectMapper.select(SelectDSLCompleter.allRowsOrderedBy(ProjectDynamicSqlSupport.id));
			});

		return projects.stream().map(entity -> { //TODO:converter
			ProjectDto dto = new ProjectDto();
			dto.setId(entity.getId());
			dto.setName(entity.getName());
			dto.setExplanation(entity.getExplanation());
			return dto;
		}).collect(Collectors.toList());
	}

	public void saveProject(ProjectDto dto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			Project entity = new Project();
			entity.setName(dto.getName());
			entity.setExplanation(dto.getExplanation());
			entity.setFkUserId(1);//TODO
			entity.setPrcDate(now);

			ProjectMapper projectMapper = session.getMapper(ProjectMapper.class);
			projectMapper.insert(entity);
			int id = SqlUtil.loadGeneratedId(session);

			dto.setId(id);
		});
	}

}
