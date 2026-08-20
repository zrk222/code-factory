import { Composition } from 'remotion';
import { FactoryEngine } from './FactoryEngine';

export const Root = () => (
  <Composition
    id="CodeFactoryFactoryEngine"
    component={FactoryEngine}
    durationInFrames={2700}
    fps={30}
    width={1920}
    height={1080}
  />
);
