import http from "k6/http";

export const options = {
  scenarios: {
    open_loop: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.RATE || 50),
      timeUnit: "1s",
      duration: __ENV.DURATION || "30s",
      preAllocatedVUs: 20,
      maxVUs: 200,
    },
  },
  thresholds: {
    dropped_iterations: ["count==0"],
  },
};

const target = __ENV.WORK_URL || "http://127.0.0.1:8090";

export default function () {
  http.get(`${target}/`, { responseCallback: http.expectedStatuses(404) });
}
