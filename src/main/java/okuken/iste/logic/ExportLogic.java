package okuken.iste.logic;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.dto.MessageDto;
import okuken.iste.dto.ProjectMemoDto;
import okuken.iste.util.UiUtil;

public class ExportLogic {

	private static final ExportLogic instance = new ExportLogic();
	private ExportLogic() {}
	public static ExportLogic getInstance() {
		return instance;
	}

	//TODO: template engine...
	public void exportMemoToTextFile(File file, List<MessageDto> messageDtos, List<ProjectMemoDto> projectMemos) {
		try (FileOutputStream fos = new FileOutputStream(file);
			OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
			BufferedWriter bw = new BufferedWriter(osw)) {

			writeln(bw, String.format("# %s [%s]", ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName(), UiUtil.now()));

			bw.newLine();

			for(int i = 0; i < projectMemos.size(); i++) {
				writeln(bw, String.format("## Project notes %d", i + 1));

				if(StringUtils.isNotBlank(projectMemos.get(i).getMemo())) {
					writeln(bw, "```");
					writeln(bw, projectMemos.get(i).getMemo());
					writeln(bw, "```");
				}

				bw.newLine();
			}

			writeln(bw, "## Request notes");
			bw.newLine();

			for(MessageDto messageDto: messageDtos) {
				writeln(bw, String.format("### %s %s", Optional.ofNullable(messageDto.getName()).orElse("No title"), messageDto.getUrlShort()));

				if(StringUtils.isNotBlank(messageDto.getRemark())) {
					writeln(bw, String.format("- Remark: %s", messageDto.getRemark()));
				}
				writeln(bw, String.format("- Progress: %s %s", messageDto.getProgress().getCaption(), Optional.ofNullable(messageDto.getProgressMemo()).orElse("")));

				if(StringUtils.isNotBlank(messageDto.getMemo())) {
					writeln(bw, "```");
					writeln(bw, messageDto.getMemo());
					writeln(bw, "```");
				}

				bw.newLine();
			}

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private void writeln(BufferedWriter bw, String str) throws IOException {
		bw.write(str);
		bw.newLine();
	}

}
