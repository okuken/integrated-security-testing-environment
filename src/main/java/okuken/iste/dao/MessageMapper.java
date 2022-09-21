package okuken.iste.dao;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.ResultMap;
import org.apache.ibatis.annotations.SelectProvider;
import org.mybatis.dynamic.sql.select.render.SelectStatementProvider;
import org.mybatis.dynamic.sql.util.SqlProviderAdapter;

import okuken.iste.entity.Message;

@Mapper
public interface MessageMapper extends okuken.iste.dao.auto.MessageMapper {

	@SelectProvider(type = SqlProviderAdapter.class, method = "select")
	@ResultMap("MessageJoinResultMap")
	Message selectOneJoin(SelectStatementProvider selectStatement);

	@SelectProvider(type = SqlProviderAdapter.class, method = "select")
	@ResultMap("MessageJoinResultMap")
	List<Message> selectManyJoin(SelectStatementProvider selectStatement);

}
