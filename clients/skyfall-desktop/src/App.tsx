import { Box, Group, MantineProvider, Text } from "@mantine/core";
import { shadcnTheme } from "./theme/theme";
import { shadcnCssVariableResolver } from "./theme/cssVariableResolver";
import "./theme/style.css";
import "./styles/index.scss";
import { useTranslation } from "react-i18next";
import { WindowTitlebar } from "tauri-controls"
import { TbCloudDownload } from "react-icons/tb";
import { Outlet } from "react-router";


export function App() {
    const {t} = useTranslation();
    return <MantineProvider theme={shadcnTheme} cssVariablesResolver={shadcnCssVariableResolver} defaultColorScheme="dark">
        <WindowTitlebar className="titlebar" windowControlsProps={{className: "titlebar-buttons", platform: "windows"}}>
            <Group gap="sm" className="titlebar-content" justify="start" align="center">
                <TbCloudDownload size={20} style={{transform: "translate(0, -1px)"}} />
                <Text fw="500" ff="monospace">{t("common.appName")}</Text>
            </Group>
        </WindowTitlebar>
        <Box p="xs" className="app-main">
            <Outlet />
        </Box>
    </MantineProvider>
}
