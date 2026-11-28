/**
 * Whether NeoDesk is installed on this computer, as far as the browser
 * lets a page see it. An installed NeoDesk puts the font "NeoDesk Marker"
 * on the computer (neodesk-client, res/marker-font): one empty glyph "Q",
 * three em wide. Text in that font measures 12 em for "QQQQ"; without it
 * the fallback font draws narrow letters.
 *
 * Chrome and Edge see fonts the user installed. Safari shows pages only
 * the fonts macOS ships, and Firefox and Brave may hide or blur them, so
 * false means "don't know", never "not installed".
 */

export const MARKER_FONT = 'NeoDesk Marker';

const SIZE = 40;
const PROBE = 'QQQQ';
/** Four Qs of three em each */
const MARKED_WIDTH = SIZE * 3 * PROBE.length;

export function neodeskInstalled(doc: Document = document): boolean {
	let ctx: CanvasRenderingContext2D | null;
	try {
		ctx = doc.createElement('canvas').getContext('2d');
	} catch {
		return false;
	}
	if (!ctx) return false;
	ctx.font = `${SIZE}px monospace`;
	const plain = ctx.measureText(PROBE).width;
	ctx.font = `${SIZE}px "${MARKER_FONT}", monospace`;
	const marked = ctx.measureText(PROBE).width;
	return Math.abs(marked - MARKED_WIDTH) < 1 && Math.abs(plain - MARKED_WIDTH) >= 1;
}
