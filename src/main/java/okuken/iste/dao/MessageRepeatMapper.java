package okuken.iste.dao;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.ResultMap;
import org.apache.ibatis.annotations.SelectProvider;
import org.mybatis.dynamic.sql.select.render.SelectStatementProvider;
import org.mybatis.dynamic.sql.util.SqlProviderAdapter;

import okuken.iste.entity.MessageRepeat;

@Mapper
public interface MessageRepeatMapper extends okuken.iste.dao.auto.MessageRepeatMapper {

	@SelectProvider(type = SqlProviderAdapter.class, method = "select")
	@ResultMap("MessageRepeatJoinResultMap")
	List<MessageRepeat> selectManyWithRedir(SelectStatementProvider selectStatement);

}
