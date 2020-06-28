package okuken.iste.dao;

import org.apache.ibatis.annotations.Select;

public interface MessageDao {

    @Select("SELECT COUNT(*) FROM STM_MSG")
    public int getCount();

}
