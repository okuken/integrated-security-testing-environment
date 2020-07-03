package okuken.iste.logic;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.ibatis.session.SqlSession;
import org.mybatis.dynamic.sql.select.SelectDSLCompleter;

import okuken.iste.DatabaseManager;
import okuken.iste.dao.ProjectMapper;
import okuken.iste.dto.ProjectDto;
import okuken.iste.entity.Project;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.SqlUtil;
import okuken.iste.view.option.ProjectSelectorDialog;

public class ProjectLogic {

	private static final ProjectLogic instance = new ProjectLogic();
	private ProjectLogic() {}
	public static ProjectLogic getInstance() {
		return instance;
	}

	public void selectProject() {
		ProjectSelectorDialog projectSelectorDialog = new ProjectSelectorDialog();
		BurpUtil.getCallbacks().customizeUiComponent(projectSelectorDialog);
		projectSelectorDialog.setVisible(true);
		ProjectDto projectDto = projectSelectorDialog.getSelectedProject();

		if(projectDto.getId() == null) {
			saveProject(projectDto);
		}
		ConfigLogic.getInstance().setProject(projectDto);
	}

	public List<ProjectDto> loadProjects() {
		try {
			List<Project> projects;
			try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
				ProjectMapper projectMapper = session.getMapper(ProjectMapper.class);
				projects = projectMapper.select(SelectDSLCompleter.allRows()); //TODO: order by id desc??
			}

			return projects.stream().map(entity -> { //TODO:converter
				ProjectDto dto = new ProjectDto();
				dto.setId(entity.getId());
				dto.setName(entity.getName());
				dto.setExplanation(entity.getExplanation());
				return dto;
			}).collect(Collectors.toList());

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public void saveProject(ProjectDto dto) {
		try {
			String now = SqlUtil.now();
			try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
				Project entity = new Project();
				entity.setName(dto.getName());
				entity.setExplanation(dto.getExplanation());
				entity.setFkUserId(1);//TODO
				entity.setPrcDate(now);

				ProjectMapper projectMapper = session.getMapper(ProjectMapper.class);
				projectMapper.insert(entity);
				int id = SqlUtil.loadGeneratedId(session);

				dto.setId(id);

				session.commit();
			}
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
		//TODO: rollback controll???
	}

}
