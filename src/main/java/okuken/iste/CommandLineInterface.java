package okuken.iste;

import java.io.File;

import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

public class CommandLineInterface {

	@Option(name="-makeCleanDb", usage="make ISTE clean database file.")
	private File cleanDbFile = null;

	@Option(name="-f", usage="force.")
	private boolean force = false;

	public static void main(String[] args) {
		new CommandLineInterface().doMain(args);
	}

	public void doMain(String[] args) {
		CmdLineParser parser = new CmdLineParser(this);

		try {

			parser.parseArgument(args);
	
			if(cleanDbFile != null) {
				makeCleanDb();
				return;
			}

		} catch(Exception e) {
			System.err.println("ERROR: " + e.getMessage());
		}
		System.err.println("[USEAGE]");
		parser.printUsage(System.err);
		System.exit(1);
	}

	private void makeCleanDb() {
		if(cleanDbFile.exists()) {
			if(!force) {
				throw new IllegalArgumentException(cleanDbFile.getAbsolutePath() + " is exists. If you intend to overwrite, add -f option.");
			}
			cleanDbFile.delete();
		}

		var databaseManager = DatabaseManager.getInstance();
		databaseManager.setupDatabase(cleanDbFile.getAbsolutePath());
		databaseManager.unloadDatabase();
		return;
	}

}
