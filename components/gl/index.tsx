import { Effects } from "@react-three/drei";
import { Canvas } from "@react-three/fiber";
import { Particles } from "./particles";
import { VignetteShader } from "./shaders/vignetteShader";

// Lumina particle configuration
const CONFIG = {
  speed: 0.8,
  noiseScale: 0.5,
  noiseIntensity: 0.44,
  timeScale: 0.8,
  focus: 4.2,
  aperture: 1.65,
  pointSize: 9.0,
  opacity: 0.9,
  planeScale: 10.0,
  size: 256,
  vignetteDarkness: 1.9,
  vignetteOffset: 0.32,
} as const;

export const GL = ({
  hovering,
  useManualTime = false,
  manualTime = 0,
}: {
  hovering: boolean;
  useManualTime?: boolean;
  manualTime?: number;
}) => {
  return (
    <div
      id="webgl"
      style={{
        top: 0,
        left: 0,
        position: "fixed",
        height: "100svh",
        width: "100%",
        zIndex: 0,
        pointerEvents: "none",
      }}
    >
      <Canvas
        style={{ width: "100%", height: "100%" }}
        camera={{
          position: [1.26, 2.66, -1.82],
          fov: 50,
          near: 0.01,
          far: 300,
        }}
      >
        <color attach="background" args={["#080810"]} />
        <Particles
          speed={CONFIG.speed}
          aperture={CONFIG.aperture}
          focus={CONFIG.focus}
          size={CONFIG.size}
          noiseScale={CONFIG.noiseScale}
          noiseIntensity={CONFIG.noiseIntensity}
          timeScale={CONFIG.timeScale}
          pointSize={CONFIG.pointSize}
          opacity={CONFIG.opacity}
          planeScale={CONFIG.planeScale}
          useManualTime={useManualTime}
          manualTime={manualTime}
          introspect={hovering}
        />
        <Effects multisamping={0} disableGamma>
          <shaderPass
            args={[VignetteShader]}
            uniforms-darkness-value={CONFIG.vignetteDarkness}
            uniforms-offset-value={CONFIG.vignetteOffset}
          />
        </Effects>
      </Canvas>
    </div>
  );
};
