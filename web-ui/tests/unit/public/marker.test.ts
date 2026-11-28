/**
 * The marker font check: "QQQQ" in "NeoDesk Marker" is 12 em wide when
 * an installed NeoDesk put the font on the computer.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { neodeskInstalled } from '../../../src/lib/public/marker.ts';

/** A canvas whose text widths depend on the font it is asked for */
function canvasMeasuring(width: (font: string) => number | null) {
	vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(function () {
		const ctx = {
			font: '',
			measureText(text: string) {
				return { width: (width(ctx.font) ?? 0) * (text.length / 4) };
			}
		};
		return ctx as unknown as CanvasRenderingContext2D;
	} as typeof HTMLCanvasElement.prototype.getContext);
}

afterEach(() => vi.restoreAllMocks());

describe('neodeskInstalled', () => {
	test('true when the marker font draws four Qs 480 px wide at 40 px', () => {
		canvasMeasuring((font) => (font.includes('"NeoDesk Marker"') ? 480 : 96));
		expect(neodeskInstalled()).toBe(true);
	});

	test('false when the font is missing and the fallback draws the Qs', () => {
		canvasMeasuring(() => 96);
		expect(neodeskInstalled()).toBe(false);
	});

	test('false for another wide font that is not three em per Q', () => {
		canvasMeasuring((font) => (font.includes('"NeoDesk Marker"') ? 300 : 96));
		expect(neodeskInstalled()).toBe(false);
	});

	test('false without a canvas', () => {
		vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
		expect(neodeskInstalled()).toBe(false);
	});
});
