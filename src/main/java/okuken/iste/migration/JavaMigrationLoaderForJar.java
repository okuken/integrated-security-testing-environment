package okuken.iste.migration;

import java.io.Reader;
import java.io.StringReader;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.ibatis.migration.Change;
import org.apache.ibatis.migration.MigrationLoader;
import org.apache.ibatis.migration.MigrationScript;

import com.google.common.reflect.ClassPath;
import com.google.common.reflect.ClassPath.ClassInfo;

import okuken.iste.migration.scripts.Bootstrap;
import okuken.iste.migration.scripts.PrefixedMigrationScript;

/**
 * Custom MigrationLoader because org.apache.ibatis.migration.JavaMigrationLoader doesn't work in my environment. 
 */
public class JavaMigrationLoaderForJar implements MigrationLoader {

	private ClassLoader classLoader;
	private String packageName;

	public JavaMigrationLoaderForJar(ClassLoader classLoader, String packageName) {
		this.classLoader = classLoader;
		this.packageName = packageName;
	}

	@Override
	public List<Change> getMigrations() {
		try {
			return ClassPath.from(classLoader).getTopLevelClasses(packageName).stream()
				.filter(classInfo -> classInfo.getSimpleName().matches("V\\d{" + PrefixedMigrationScript.VERSION_NUMBER_LENGTH + "}_.*"))
				.map(this::createMigrationScriptInstance)
				.map(this::convertMigrationScriptToChange)
				.collect(Collectors.toList());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	private MigrationScript createMigrationScriptInstance(ClassInfo migrationScriptClassInfo) {
		try {
			return (MigrationScript)migrationScriptClassInfo.load().getDeclaredConstructor().newInstance();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	private Change convertMigrationScriptToChange(MigrationScript script) {
		var ret = new Change();
		ret.setId(script.getId());
		ret.setDescription(script.getDescription());
		ret.setFilename(script.getClass().getName());
		return ret;
	}

	@Override
	public Reader getScriptReader(Change change, boolean undo) {
		MigrationScript migrationScript;
		try {
			migrationScript = (MigrationScript)Class.forName(change.getFilename(), true, classLoader).getDeclaredConstructor().newInstance();
			return new StringReader(undo ? migrationScript.getDownScript() : migrationScript.getUpScript());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Reader getBootstrapReader() {
		return new StringReader(new Bootstrap().getScript());
	}

	@Override
	public Reader getOnAbortReader() {
		return null;
	}

}
