using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace beratoksz.Migrations
{
    /// <inheritdoc />
    public partial class UpdateActivityLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<double>(
                name: "Duration",
                table: "ActivityLogs",
                type: "float",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<string>(
                name: "IPAddress",
                table: "ActivityLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "OS",
                table: "ActivityLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "UserAgent",
                table: "ActivityLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Duration",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "IPAddress",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "OS",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "UserAgent",
                table: "ActivityLogs");
        }
    }
}
