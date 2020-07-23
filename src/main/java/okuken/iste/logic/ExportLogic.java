package okuken.iste.logic;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import okuken.iste.dto.MessageDto;
import okuken.iste.dto.ProjectMemoDto;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

public class ExportLogic {

	private static final ExportLogic instance = new ExportLogic();
	private ExportLogic() {}
	public static ExportLogic getInstance() {
		return instance;
	}

	public void exportMemoToTextFile(File file, List<MessageDto> messageDtos, List<ProjectMemoDto> projectMemos) {
		try (FileOutputStream fos = new FileOutputStream(file);
			OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
			BufferedWriter bw = new BufferedWriter(osw)) {

			bw.write(String.format("# %s [%s]", ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName(), UiUtil.now()));
			bw.newLine();
			bw.newLine();

			for(int i = 0; i < projectMemos.size(); i++) {
				bw.write(String.format("## Project memo %d", i + 1));
				bw.newLine();
				bw.newLine();
				bw.write(Optional.ofNullable(projectMemos.get(i).getMemo()).orElse(""));
				bw.newLine();
				bw.newLine();
			}

			bw.write("## Requests memo");
			bw.newLine();
			bw.newLine();

			for(MessageDto messageDto: messageDtos) {
				bw.write(String.format("### %s\t%s", messageDto.getName(), messageDto.getUrlShort()));
				bw.newLine();

				if(messageDto.getRemark() != null && !messageDto.getRemark().isBlank()) {
					bw.write(messageDto.getRemark());
					bw.newLine();
				}
				bw.write(String.format("Progress: %s %s", messageDto.getProgress().getCaption(), Optional.ofNullable(messageDto.getProgressMemo()).orElse("")));
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
