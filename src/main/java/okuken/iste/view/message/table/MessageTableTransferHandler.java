package okuken.iste.view.message.table;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.TransferHandler;

import okuken.iste.dto.MessageDto;

public class MessageTableTransferHandler extends TransferHandler {

	private static final long serialVersionUID = 1L;

	protected static final DataFlavor DATA_FLAVOR_MESSAGES = new DataFlavor(List.class, "List of Messages");

	private JTable table;
	private MessageTableModel messageTableModel;

	private int[] selectedRowIndexs;
	private Integer targetIndex;

	public MessageTableTransferHandler(JTable table, MessageTableModel tableModel) {
		super();
		this.table = table;
		this.messageTableModel = tableModel;
	}

	@Override
	protected Transferable createTransferable(JComponent c) {
		this.selectedRowIndexs = table.getSelectedRows();
		List<MessageDto> selectedRows = Arrays.stream(this.selectedRowIndexs).mapToObj(messageTableModel::getRow).collect(Collectors.toList());

		return new Transferable() {
			@Override
			public DataFlavor[] getTransferDataFlavors() {
				return new DataFlavor[] { DATA_FLAVOR_MESSAGES };
			}

			@Override
			public boolean isDataFlavorSupported(DataFlavor flavor) {
				return DATA_FLAVOR_MESSAGES.equals(flavor);
			}

			@Override
			public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
				if (isDataFlavorSupported(flavor)) {
					return selectedRows;
				}
				throw new UnsupportedFlavorException(flavor);
			}
		};
	}

	@Override
	public boolean importData(TransferSupport support) {
		DropLocation dropLocation = support.getDropLocation();
		if (!(dropLocation instanceof JTable.DropLocation)) {
			return false;
		}

		this.targetIndex = ((JTable.DropLocation) dropLocation).getRow();

		try {
			@SuppressWarnings("unchecked")
			List<MessageDto> messageDtos = (List<MessageDto>) support.getTransferable().getTransferData(DATA_FLAVOR_MESSAGES);
			messageTableModel.insertRows(this.targetIndex, messageDtos);
			table.getSelectionModel().addSelectionInterval(this.targetIndex, this.targetIndex + messageDtos.size() - 1);
			return true;
		} catch (UnsupportedFlavorException | IOException ex) {
			return false;
		}
	}

	@Override
	protected void exportDone(JComponent c, Transferable data, int action) {
		if(action != TransferHandler.MOVE) { //table header
			return;
		}

		List<Integer> selectedRowAfterIndexs = Arrays.stream(selectedRowIndexs)
				.mapToObj(selectedRowIndex -> selectedRowIndex < targetIndex ? selectedRowIndex : selectedRowIndex + selectedRowIndexs.length)
				.collect(Collectors.toList());

		Collections.reverse(selectedRowAfterIndexs);
		selectedRowAfterIndexs.stream().forEach(selectedRowAfterIndex -> messageTableModel.removeRow(selectedRowAfterIndex));
	}

	@Override
	public boolean canImport(TransferSupport support) {
		return support.isDrop() && support.isDataFlavorSupported(DATA_FLAVOR_MESSAGES);
	}

	@Override
	public int getSourceActions(JComponent c) {
		return TransferHandler.MOVE;
	}

}