package okuken.iste.logic;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import com.google.common.base.Optional;

import static org.mybatis.dynamic.sql.SqlBuilder.*;

import static okuken.iste.dao.auto.CommonOrdDynamicSqlSupport.*;
import okuken.iste.dao.auto.CommonOrdMapper;
import okuken.iste.entity.auto.CommonOrd;
import okuken.iste.enums.OrderType;
import okuken.iste.interfaces.Orderable;
import okuken.iste.util.DbUtil;
import okuken.iste.util.SqlUtil;

public class OrderLogic {

	private static final String DELIM = ",";

	private static final OrderLogic instance = new OrderLogic();
	private OrderLogic() {}
	public static OrderLogic getInstance() {
		return instance;
	}

	/**
	 * insert or update.
	 */
	public void saveOrder(List<? extends Orderable> dtos, OrderType orderType) {
		saveOrderByIds(dtos.stream().map(Orderable::getId).collect(Collectors.toList()), orderType);
	}
	private void saveOrderByIds(List<Integer> ord, OrderType orderType) {
		String ordStr = ord.stream().map(i -> i.toString()).collect(Collectors.joining(DELIM));
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			var mapper = session.getMapper(CommonOrdMapper.class);

			var entityOptional = mapper.selectOne(c -> c
					.where(fkProjectId, isEqualTo(ConfigLogic.getInstance().getProjectId()))
					.and(ordType, isEqualTo(orderType.getId())));

			if(entityOptional.isPresent()) {
				var entity = entityOptional.get();
				entity.setOrd(ordStr);
				entity.setPrcDate(now);
				mapper.updateByPrimaryKey(entity);
				return;
			}

			var entity = new CommonOrd();
			entity.setFkProjectId(ConfigLogic.getInstance().getProjectId());
			entity.setOrdType(orderType.getId());
			entity.setOrd(ordStr);
			entity.setPrcDate(now);
			mapper.insert(entity);
		});
	}

	private Optional<List<Integer>> loadOrder(OrderType orderType) {
		var entity = DbUtil.withSession(session -> {
			var mapper = session.getMapper(CommonOrdMapper.class);
			return mapper.selectOne(c -> c
					.where(fkProjectId, isEqualTo(ConfigLogic.getInstance().getProjectId()))
					.and(ordType, isEqualTo(orderType.getId())));
		});

		if(entity.isEmpty()) {
			return Optional.absent();
		}

		var ordStr = entity.get().getOrd();
		if(StringUtils.isEmpty(ordStr)) {
			return Optional.absent();
		}

		return Optional.of(
			Arrays.stream(ordStr.split(DELIM)).map(Integer::parseInt).collect(Collectors.toList()));
	}

	@SuppressWarnings("unchecked")
	public <T> List<T> sortByOrder(List<? extends Orderable> dtos, OrderType orderType) {
		var order = loadOrder(orderType);
		if(!order.isPresent()) {
			return (List<T>)dtos;
		}
		return (List<T>)order.get().stream()
				.map(id -> dtos.stream().filter(dto -> dto.getId().equals(id)).findFirst().get())
				.collect(Collectors.toList());
	}

}
