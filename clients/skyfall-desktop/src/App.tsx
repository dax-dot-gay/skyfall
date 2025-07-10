import { Box, Button, MantineProvider } from "@mantine/core";
import { shadcnTheme } from "./theme/theme";
import { shadcnCssVariableResolver } from "./theme/cssVariableResolver";
import "./theme/style.css";

export function App() {
    return <MantineProvider theme={shadcnTheme} cssVariablesResolver={shadcnCssVariableResolver} defaultColorScheme="dark">
        <Box p="sm">
            <Button variant="light">TEST</Button>
        </Box>
    </MantineProvider>
}
