package okuken.iste.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

class ReflectionUtilTest {

	class Obj {
		private String field01;
		private String field02;
		private String field03;

		public Obj(String field01, String field02, String field03) {
			this.field01 = field01;
			this.field02 = field02;
			this.field03 = field03;
		}

		public String getField01() {
			return field01;
		}
		public String getField02() {
			return field02;
		}
		public String getField03() {
			return field03;
		}
		public void setField01(String field01) {
			this.field01 = field01;
		}
		public void setField02(String field02) {
			this.field02 = field02;
		}
		public void setField03(String field03) {
			this.field03 = field03;
		}
	}

	@Test
	void setToNumberedFields_byList() {
		var source = Arrays.asList("a", "b");
		var dest = new Obj("z", "z", "z");
		ReflectionUtil.setNumberedFields(dest, "setField%02d", 1, 3, String.class, source);

		assertEquals("a", dest.getField01());
		assertEquals("b", dest.getField02());
		assertNull(dest.getField03());
	}

	@Test
	void setToNumberedFields_byObj() {
		var source = new Obj("a", "b", "c");
		var dest   = new Obj("z", "z", "z");
		ReflectionUtil.setNumberedFields(dest, "setField%02d", 1, 3, String.class, source, "getField%02d");

		assertEquals("a", dest.getField01());
		assertEquals("b", dest.getField02());
		assertEquals("c", dest.getField03());
	}

	@Test
	void getNumberedFieldValuesAsList() {
		var source = new Obj("a", "b", "c");
		var result = ReflectionUtil.getNumberedFieldsAsList(source, "getField%02d", 1, 3);
		assertArrayEquals(Arrays.asList("a", "b", "c").toArray(), result.toArray());
	}

}
