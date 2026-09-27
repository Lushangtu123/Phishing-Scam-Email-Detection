import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {checkImage, dataImages, decodeQRs} from './vision-core.mjs';
import * as visionCore from './vision-core.mjs';
const require = createRequire(import.meta.url);
const jsQR = require('./vendor/vision/jsQR.js');
const matrices = JSON.parse(readFileSync(new URL('../tests/fixtures/vision/qr-matrices.json', import.meta.url)));
function qrPixels(items) {
  const width = items.length * 500, height = 500;
  const data = new Uint8ClampedArray(width * height * 4).fill(255);
  items.forEach((item,n) => item.matrix.forEach((row,y) => row.forEach((on,x) => {
    if (on) for (let dy=0;dy<10;dy++) for(let dx=0;dx<10;dx++) {
      const offset = ((50+y*10+dy)*width+n*500+50+x*10+dx)*4;
      data[offset]=data[offset+1]=data[offset+2]=0;
    }
  })));
  return {width,height,data};
}
test('real QR decoder reads a synthetic phishing URL without modifying input', () => {
  const image=qrPixels([matrices[1]]), before=image.data.slice();
  assert.deepEqual(decodeQRs(image,jsQR).values,[matrices[1].text]);
  assert.deepEqual(image.data,before);
});
test('two separate QR codes both contribute their exact payloads', () => {
  assert.deepEqual(new Set(decodeQRs(qrPixels(matrices),jsQR).values),new Set(matrices.map(m=>m.text)));
});
test('OCR copy excludes both codes even when their payload is identical', () => {
  const image=qrPixels([matrices[1],matrices[1]]), before=image.data.slice();
  const result=decodeQRs(image,jsQR);
  assert.deepEqual(result.values,[matrices[1].text]);
  assert(result.ocrImage.data.every(value=>value===255));
  assert.deepEqual(image.data,before);
});
test('quadrant-decoded QR geometry is translated to full-image coordinates', () => {
  const image={width:100,height:100,data:new Uint8ClampedArray(40000).fill(0)};
  let calls=0;
  const result=decodeQRs(image,(_pixels,width)=> {
    if (width===100 || ++calls!==2) return null;
    return {data:'payload',location:{topLeftCorner:{x:10,y:10},topRightCorner:{x:30,y:10},bottomRightCorner:{x:30,y:30},bottomLeftCorner:{x:10,y:30}}};
  });
  // The second quadrant is top-right, after full-image and top-left misses.
  assert.equal(result.ocrImage.data[(15*100+55)*4],255);
  assert.equal(result.ocrImage.data[(15*100+15)*4],0);
  assert(image.data.every(value=>value===0));
});
test('rotated QR mask preserves dark pixels in the corners of its bounding box', () => {
  const image={width:100,height:100,data:new Uint8ClampedArray(40000).fill(0)};
  let calls=0;
  const result=decodeQRs(image,()=> ++calls===1 ? {data:'payload',location:{topLeftCorner:{x:50,y:10},topRightCorner:{x:90,y:50},bottomRightCorner:{x:50,y:90},bottomLeftCorner:{x:10,y:50}}} : null);
  assert.equal(result.ocrImage.data[(50*100+50)*4],255);
  assert.equal(result.ocrImage.data[(15*100+15)*4],0);
  assert.equal(result.ocrImage.data[(15*100+85)*4],0);
  assert.equal(result.ocrImage.data[(85*100+85)*4],0);
  assert.equal(result.ocrImage.data[(85*100+15)*4],0);
});
test('an undecodable image keeps all original pixels in a distinct OCR copy', () => {
  const image={width:10,height:10,data:Uint8ClampedArray.from({length:400},(_,i)=>i%256)};
  const result=decodeQRs(image,()=>null);
  assert.deepEqual(result.values,[]);
  assert.deepEqual(result.ocrImage.data,image.data);
  assert.notEqual(result.ocrImage.data,image.data);
});
test('URL-like OCR line confidence is independent of the page average and does not repair text', () => {
  const blocks=[{paragraphs:[{lines:[
    {text:'Verify your account now',confidence:95},
    {text:'https://paypal.example/login',confidence:48},
    {text:'httbs:/ /baybal.example/login',confidence:80},
  ]}]}];
  assert.equal(visionCore.urlLineConfidence(blocks),48);
  assert.equal(blocks[0].paragraphs[0].lines[1].text,'https://paypal.example/login');
  assert.equal(visionCore.urlLineConfidence([{paragraphs:[{lines:[{text:'Team meeting',confidence:99}]}]}]),null);
  assert.equal(visionCore.urlLineConfidence([{paragraphs:[{lines:[{text:'Project Q3.2026 review notes',confidence:98}]}]}]),null);
  assert.equal(visionCore.urlLineConfidence([{paragraphs:[{lines:[{text:'paypa1.examp1e/login',confidence:40}]}]}]),40);
  assert.equal(visionCore.urlLineConfidence([{paragraphs:[{lines:[{text:'https://example.com',confidence:Infinity}]}]}]),null);
});
test('a QR polygon crossing image edges cannot mask unrelated rows or columns', () => {
  const image={width:30,height:30,data:new Uint8ClampedArray(3600).fill(0)};
  let calls=0;
  const result=decodeQRs(image,()=> ++calls===1 ? {data:'payload',location:{topLeftCorner:{x:-4,y:-2},topRightCorner:{x:3,y:10},bottomRightCorner:{x:0,y:20},bottomLeftCorner:{x:-9,y:8}}} : null);
  assert.equal(result.ocrImage.data[(25*30+25)*4],0);
  assert.equal(result.ocrImage.data[(10*30+1)*4],255);
  assert.deepEqual(image.data,new Uint8ClampedArray(3600));
});
test('damaged, oversized dimension and non-image input are rejected before bitmap decode', () => {
  assert.throws(()=>checkImage(new ArrayBuffer(0)),/nonempty/);
  assert.throws(()=>checkImage(new TextEncoder().encode('<svg onload="bad()"/>').buffer),/Unsupported/);
  const png = new Uint8Array(24), view=new DataView(png.buffer);
  png.set([137,80,78,71],0); png.set([73,72,68,82],12);view.setUint32(16,100000);view.setUint32(20,100000);
  assert.throws(()=>checkImage(png.buffer),/megapixels/);
});
test('data images are extracted as bytes and remote URLs remain warnings only', () => {
  const result=dataImages('<img src="data:image/png;base64,aGVsbG8="><img src="https://example.com/track"><script>bad()</script>');
  assert.equal(new TextDecoder().decode(result.images[0].buffer),'hello');
  assert.equal(result.images.length,1);
  assert.match(result.warnings.join(' '),/Remote images/);
});

const {collectEmail} = await import('./vision-email.mjs');
test('real MIME parser extracts inline and attached images as original bytes', async () => {
  const raw=readFileSync(new URL('../tests/fixtures/vision/synthetic-images.eml',import.meta.url));
  const images=[],warnings=[];
  await collectEmail(raw,images,warnings);
  assert.equal(images.length,2);
  assert.equal(images[0].name,'payment-qr.png');
  assert.deepEqual(Buffer.from(images[0].buffer),readFileSync(new URL('../tests/fixtures/vision/synthetic-qr.png',import.meta.url)));
  assert.equal(images[1].source,'mime');
  assert.equal(warnings.length,0);
});
test('MIME extraction caps image count and surfaces the uninspected remainder',async()=>{
  const raw=['MIME-Version: 1.0','Content-Type: multipart/mixed; boundary="X"','','body'];
  for(let n=0;n<6;n++) raw.push('--X','Content-Type: image/png','Content-Transfer-Encoding: base64','', 'aGVsbG8=');
  raw.push('--X--','');
  const images=[],warnings=[];
  await collectEmail(raw.join('\r\n'),images,warnings);
  assert.equal(images.length,4);assert.match(warnings.join(' '),/four-image limit/);
});
