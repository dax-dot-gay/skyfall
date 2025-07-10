import ReactDOM from "react-dom/client";
import '@mantine/core/styles.css';
import { LocalizationProvider } from "./lang";
import { RouterProvider } from "react-router";
import { router } from "./routes";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <LocalizationProvider>
        <RouterProvider router={router} />
    </LocalizationProvider>
);
