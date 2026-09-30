import {createGateway} from '../src/funnel-gateway.mjs';
const port=Number(process.env.FUNNEL_PORT||4311),apiPort=Number(process.env.PORT||4310);
if(![port,apiPort].every(p=>Number.isInteger(p)&&p>0&&p<65536))throw Error('Invalid listener port');
createGateway({origin:process.env.PUBLIC_ORIGIN,apiPort}).listen(port,'127.0.0.1',()=>console.log(`Funnel gateway: 127.0.0.1:${port}`));
