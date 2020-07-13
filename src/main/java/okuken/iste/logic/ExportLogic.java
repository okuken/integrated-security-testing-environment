package okuken.iste.logic;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;

public class ExportLogic {

	private static final ExportLogic instance = new ExportLogic();
	private ExportLogic() {}
	public static ExportLogic getInstance() {
		return instance;
	}

	public void exportMemoToTextFile(File file, List<MessageDto> messageDtos, String projectMemo) {
		try (FileOutputStream fos = new FileOutputStream(file);
			OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
			BufferedWriter bw = new BufferedWriter(osw)) {

			bw.write(ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName());
			bw.newLine();
			bw.newLine();

			bw.write(projectMemo);
			bw.newLine();
			bw.newLine();

			for(MessageDto messageDto: messageDtos) {
				bw.write(String.format("■ %s\t%s", messageDto.getName(), messageDto.getUrlShort()));
				bw.newLine();

				bw.write(Optional.ofNullable(messageDto.getRemark()).orElse(""));
				bw.newLine();
				bw.newLine();

				bw.write(messageDto.getMemo());
				bw.newLine();
				bw.newLine();
			}

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw new RuntimeException(e);
		}
	}

}
