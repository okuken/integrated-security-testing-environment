package okuken.iste.util;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.session.SqlSession;

public class SqlUtil {

	private static final String UNIXTIME_STR_NULL = "0";

	private static final DateFormat timestampFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");

	public static final String now() {
		return Long.toString(getNowUnixtimeMs());
	}
	public static final String dateToString(Date date) {
		if(date == null) {
			return UNIXTIME_STR_NULL;
		}
		return Long.toString(convertDateToUnixtimeMs(date));
	}
	public static final Date stringToDate(String dateStr) {
		if(isUnixtimeMs(dateStr)) {
			return convertUnixtimeMsToDate(dateStr);
		}
		try {
			return timestampFormat.parse(dateStr); // for backward compatibility
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}
	public static final String dateToPresentationString(Date date) {
		if(date == null) {
			return "";
		}
		return timestampFormat.format(date);
	}

	private static final long getNowUnixtimeMs() {
		return Calendar.getInstance().getTimeInMillis();
	}
	private static final boolean isUnixtimeMs(String dateStr) {
		return StringUtils.isNumeric(dateStr); //rough but enough here
	}
	private static final Date convertUnixtimeMsToDate(String unixtimeMs) {
		if(UNIXTIME_STR_NULL.equals(unixtimeMs)) {
			return null;
		}
		var cal = Calendar.getInstance();
		cal.setTimeInMillis(Long.valueOf(unixtimeMs));
		return cal.getTime();
	}
	private static final long convertDateToUnixtimeMs(Date date) {
		return date.getTime();
	}

	public static final int loadGeneratedId(SqlSession session) {
		try (Statement stmt = session.getConnection().createStatement()) {
			try(ResultSet rs = stmt.executeQuery("SELECT LAST_INSERT_ROWID()")){ //SQLite
				rs.next();
				return rs.getInt(1);
			}
		} catch (SQLException e) {
			throw new RuntimeException("fail to load generated id value.", e);
		}
	}

}
